// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

// TODO, I've implemented this as a separate entity from the cache, but I wonder if the cache
//  should be the only "front-end" for lookups, where if that misses, then we go to the catalog
//  then, if requested, do a recursive lookup... i.e. the catalog would only point to files.
use std::{borrow::Borrow, collections::HashMap, future::Future, io, io::Write};

use cfg_if::cfg_if;
use tracing::{debug, error, info, trace, warn};

use dump::{Dump, Walk};

#[cfg(feature = "dnssec")]
use crate::proto::rr::{
    dnssec::{Algorithm, SupportedAlgorithms},
    rdata::opt::{EdnsCode, EdnsOption},
};
use crate::{
    authority::{
        AuthLookup, AuthorityObject, EmptyLookup, LookupError, LookupObject, LookupOptions,
        MessageResponse, MessageResponseBuilder, ZoneType,
    },
    proto::op::{Edns, Header, LowerQuery, MessageType, OpCode, ResponseCode},
    proto::rr::{LowerName, Record, RecordType},
    server::{Request, RequestHandler, RequestInfo, ResponseHandler, ResponseInfo},
};

/// Set of authorities, zones, available to this server.
#[derive(Default)]
pub struct Catalog {
    authorities: HashMap<LowerName, Box<dyn AuthorityObject>, crate::BuildNoHasher>,
}

#[allow(unused_mut, unused_variables)]
async fn send_response<'a, R: ResponseHandler>(
    response_edns: Option<Edns>,
    mut response: MessageResponse<
        '_,
        'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
    >,
    mut response_handle: R,
) -> io::Result<ResponseInfo> {
    if let Some(mut resp_edns) = response_edns {
        #[cfg(feature = "dnssec")]
        {
            // set edns DAU and DHU
            // send along the algorithms which are supported by this authority
            let mut algorithms = SupportedAlgorithms::default();
            algorithms.set(Algorithm::RSASHA256);
            algorithms.set(Algorithm::ECDSAP256SHA256);
            algorithms.set(Algorithm::ECDSAP384SHA384);
            algorithms.set(Algorithm::ED25519);

            let dau = EdnsOption::DAU(algorithms);
            let dhu = EdnsOption::DHU(algorithms);

            resp_edns.options_mut().insert(dau);
            resp_edns.options_mut().insert(dhu);
        }
        response.set_edns(resp_edns);
    }

    response_handle.send_response(response).await
}

#[async_trait::async_trait]
impl RequestHandler for Catalog {
    /// Determines what needs to happen given the type of request, i.e. Query or Update.
    ///
    /// # Arguments
    ///
    /// * `request` - the requested action to perform.
    /// * `response_handle` - sink for the response message to be sent
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        trace!("request: {:?}", request);

        let response_edns: Option<Edns>;

        // check if it's edns
        if let Some(req_edns) = request.edns() {
            let mut response = MessageResponseBuilder::new(Some(request.raw_query()));
            let mut response_header = Header::response_from_request(request.header());

            let mut resp_edns: Edns = Edns::new();

            // check our version against the request
            // TODO: what version are we?
            let our_version = 0;
            resp_edns.set_dnssec_ok(true);
            resp_edns.set_max_payload(req_edns.max_payload().max(512));
            resp_edns.set_version(our_version);

            if req_edns.version() > our_version {
                warn!(
                    "request edns version greater than {}: {}",
                    our_version,
                    req_edns.version()
                );
                response_header.set_response_code(ResponseCode::BADVERS);
                resp_edns.set_rcode_high(ResponseCode::BADVERS.high());
                response.edns(resp_edns);

                // TODO: should ResponseHandle consume self?
                let result = response_handle
                    .send_response(response.build_no_records(response_header))
                    .await;

                // couldn't handle the request
                return match result {
                    Err(e) => {
                        error!("request error: {}", e);
                        ResponseInfo::serve_failed()
                    }
                    Ok(info) => info,
                };
            }

            response_edns = Some(resp_edns);
        } else {
            response_edns = None;
        }

        let result = match request.message_type() {
            // TODO think about threading query lookups for multiple lookups, this could be a huge improvement
            //  especially for recursive lookups
            MessageType::Query => match request.op_code() {
                OpCode::Query => {
                    debug!("query received: {}", request.id());
                    let info = self.lookup(request, response_edns, response_handle).await;

                    Ok(info)
                }
                OpCode::Update => {
                    debug!("update received: {}", request.id());
                    self.update(request, response_edns, response_handle).await
                }
                c => {
                    warn!("unimplemented op_code: {:?}", c);
                    let response = MessageResponseBuilder::new(Some(request.raw_query()));

                    response_handle
                        .send_response(response.error_msg(request.header(), ResponseCode::NotImp))
                        .await
                }
            },
            MessageType::Response => {
                warn!("got a response as a request from id: {}", request.id());
                let response = MessageResponseBuilder::new(Some(request.raw_query()));

                response_handle
                    .send_response(response.error_msg(request.header(), ResponseCode::FormErr))
                    .await
            }
        };

        match result {
            Err(e) => {
                error!("request failed: {}", e);
                ResponseInfo::serve_failed()
            }
            Ok(info) => info,
        }
    }
}

impl Catalog {
    /// Constructs a new Catalog
    pub fn new() -> Self {
        Self {
            authorities: HashMap::with_hasher(crate::BuildNoHasher),
        }
    }

    /// Insert or update a zone authority
    ///
    /// # Arguments
    ///
    /// * `name` - zone name, e.g. example.com.
    /// * `authority` - the zone data
    pub fn upsert(&mut self, name: LowerName, authority: Box<dyn AuthorityObject>) {
        self.authorities.insert(name, authority);
    }

    /// Remove a zone from the catalog
    pub fn remove(&mut self, name: &LowerName) -> Option<Box<dyn AuthorityObject>> {
        self.authorities.remove(name)
    }

    /// Update the zone given the Update request.
    ///
    /// [RFC 2136](https://tools.ietf.org/html/rfc2136), DNS Update, April 1997
    ///
    /// ```text
    /// 3.1 - Process Zone Section
    ///
    ///   3.1.1. The Zone Section is checked to see that there is exactly one
    ///   RR therein and that the RR's ZTYPE is SOA, else signal FORMERR to the
    ///   requestor.  Next, the ZNAME and ZCLASS are checked to see if the zone
    ///   so named is one of this server's authority zones, else signal NOTAUTH
    ///   to the requestor.  If the server is a zone Secondary, the request will be
    ///   forwarded toward the Primary Zone Server.
    ///
    ///   3.1.2 - Pseudocode For Zone Section Processing
    ///
    ///      if (zcount != 1 || ztype != SOA)
    ///           return (FORMERR)
    ///      if (zone_type(zname, zclass) == SECONDARY)
    ///           return forward()
    ///      if (zone_type(zname, zclass) == PRIMARY)
    ///           return update()
    ///      return (NOTAUTH)
    ///
    ///   Sections 3.2 through 3.8 describe the primary's behaviour,
    ///   whereas Section 6 describes a forwarder's behaviour.
    ///
    /// 3.8 - Response
    ///
    ///   At the end of UPDATE processing, a response code will be known.  A
    ///   response message is generated by copying the ID and Opcode fields
    ///   from the request, and either copying the ZOCOUNT, PRCOUNT, UPCOUNT,
    ///   and ADCOUNT fields and associated sections, or placing zeros (0) in
    ///   the these "count" fields and not including any part of the original
    ///   update.  The QR bit is set to one (1), and the response is sent back
    ///   to the requestor.  If the requestor used UDP, then the response will
    ///   be sent to the requestor's source UDP port.  If the requestor used
    ///   TCP, then the response will be sent back on the requestor's open TCP
    ///   connection.
    /// ```
    ///
    /// The "request" should be an update formatted message.
    ///  The response will be in the alternate, all 0's format described in RFC 2136 section 3.8
    ///  as this is more efficient.
    ///
    /// # Arguments
    ///
    /// * `request` - an update message
    /// * `response_handle` - sink for the response message to be sent
    pub async fn update<R: ResponseHandler>(
        &self,
        update: &Request,
        response_edns: Option<Edns>,
        response_handle: R,
    ) -> io::Result<ResponseInfo> {
        let request_info = update.request_info();

        let verify_request = move || -> Result<RequestInfo<'_>, ResponseCode> {
            // 2.3 - Zone Section
            //
            //  All records to be updated must be in the same zone, and
            //  therefore the Zone Section is allowed to contain exactly one record.
            //  The ZNAME is the zone name, the ZTYPE must be SOA, and the ZCLASS is
            //  the zone's class.

            let ztype = request_info.query.query_type();

            if ztype != RecordType::SOA {
                warn!(
                    "invalid update request zone type must be SOA, ztype: {}",
                    ztype
                );
                return Err(ResponseCode::FormErr);
            }

            Ok(request_info)
        };

        // verify the zone type and number of zones in request, then find the zone to update
        let request_info = verify_request();
        let authority = request_info.as_ref().map_err(|e| *e).and_then(|info| {
            self.find(info.query.name())
                .map(|a| a.box_clone())
                .ok_or(ResponseCode::Refused)
        });

        let response_code = match authority {
            Ok(authority) => {
                #[allow(deprecated)]
                match authority.zone_type() {
                    ZoneType::Secondary | ZoneType::Slave => {
                        error!("secondary forwarding for update not yet implemented");
                        ResponseCode::NotImp
                    }
                    ZoneType::Primary | ZoneType::Master => {
                        let update_result = authority.update(update).await;
                        match update_result {
                            // successful update
                            Ok(..) => ResponseCode::NoError,
                            Err(response_code) => response_code,
                        }
                    }
                    _ => ResponseCode::NotAuth,
                }
            }
            Err(response_code) => response_code,
        };

        let response = MessageResponseBuilder::new(Some(update.raw_query()));
        let mut response_header = Header::default();
        response_header.set_id(update.id());
        response_header.set_op_code(OpCode::Update);
        response_header.set_message_type(MessageType::Response);
        response_header.set_response_code(response_code);

        send_response(
            response_edns,
            response.build_no_records(response_header),
            response_handle,
        )
        .await
    }

    /// Checks whether the `Catalog` contains DNS records for `name`
    ///
    /// Use this when you know the exact `LowerName` that was used when
    /// adding an authority and you don't care about the authority it
    /// contains. For public domain names, `LowerName` is usually the
    /// top level domain name like `example.com.`.
    ///
    /// If you do not know the exact domain name to use or you actually
    /// want to use the authority it contains, use `find` instead.
    pub fn contains(&self, name: &LowerName) -> bool {
        self.authorities.contains_key(name)
    }

    /// Given the requested query, lookup and return any matching results.
    ///
    /// # Arguments
    ///
    /// * `request` - the query message.
    /// * `response_handle` - sink for the response message to be sent
    pub async fn lookup<R: ResponseHandler>(
        &self,
        request: &Request,
        response_edns: Option<Edns>,
        response_handle: R,
    ) -> ResponseInfo {
        let request_info = request.request_info();
        let authority = self.find(request_info.query.name());
        for (k, v) in self.authorities.iter() {
            println!("k={}, {}", k, k.is_fqdn());
            println!("v={}, {}", v.origin(), v.origin().is_fqdn());
        }
        if let Some(authority) = authority {
            lookup(
                request_info,
                authority,
                request,
                response_edns
                    .as_ref()
                    .map(|arc| Borrow::<Edns>::borrow(arc).clone()),
                response_handle.clone(),
            )
            .await
        } else {
            // if this is empty then the there are no authorities registered that can handle the request
            let response = MessageResponseBuilder::new(Some(request.raw_query()));

            let result = send_response(
                response_edns,
                response.error_msg(request.header(), ResponseCode::Refused),
                response_handle,
            )
            .await;

            match result {
                Err(e) => {
                    error!("failed to send response: {}", e);
                    ResponseInfo::serve_failed()
                }
                Ok(r) => r,
            }
        }
    }

    /// Recursively searches the catalog for a matching authority
    pub fn find(&self, name: &LowerName) -> Option<&(dyn AuthorityObject + 'static)> {
        debug!("searching authorities for: {}", name);
        self.authorities
            .get(name)
            .map(|authority| &**authority)
            .or_else(|| {
                if !name.is_root() {
                    let name = name.base_name();
                    self.find(&name)
                } else {
                    None
                }
            })
    }
}

#[inline(never)]
async fn lookup<'a, R: ResponseHandler + Unpin>(
    request_info: RequestInfo<'_>,
    authority: &dyn AuthorityObject,
    request: &Request,
    response_edns: Option<Edns>,
    response_handle: R,
) -> ResponseInfo {
    let mut f = Vec::new();
    _ = write!(f, "{{");

    _ = write!(f, "\"%request_info\": {{ \"data\": [\"{:p}\", \"{:p}\"], \"base\": \"{:p}\" }}, ", request_info.header, request_info.query, request);

    // dump_dyn(authority, &mut f);
    authority.dump(&mut f);
    authority.walk(&mut f);

    request.dump(&mut f);
    request.walk(&mut f);

    request_info.dump(&mut f);
    request_info.walk(&mut f);

    while let Some(ch) = f.pop() {
        if ch == b',' {
            _ = write!(f, "}}");
            break;
        }
    }

    let json = std::str::from_utf8(&f).unwrap().to_string();
    let mut outfile = std::fs::File::create("ctx.json").unwrap();
    outfile.write_all(json.as_bytes()).unwrap();

    let query = request_info.query;
    debug!(
        "request: {} found authority: {}",
        request.id(),
        authority.origin()
    );

    let (response_header, sections) = build_response(
        authority,
        request_info,
        request.id(),
        request.header(),
        query,
        request.edns(),
    )
    .await;

    let response = MessageResponseBuilder::new(Some(request.raw_query())).build(
        response_header,
        sections.answers.iter(),
        sections.ns.iter(),
        sections.soa.iter(),
        sections.additionals.iter(),
    );

    let result = send_response(response_edns.clone(), response, response_handle.clone()).await;

    match result {
        Err(e) => {
            error!("error sending response: {}", e);
            ResponseInfo::serve_failed()
        }
        Ok(i) => i,
    }
}

#[allow(unused_variables)]
fn lookup_options_for_edns(edns: Option<&Edns>) -> LookupOptions {
    let edns = match edns {
        Some(edns) => edns,
        None => return LookupOptions::default(),
    };

    cfg_if! {
        if #[cfg(feature = "dnssec")] {
            let supported_algorithms = if let Some(&EdnsOption::DAU(algs)) = edns.option(EdnsCode::DAU)
            {
               algs
            } else {
               debug!("no DAU in request, used default SupportAlgorithms");
               SupportedAlgorithms::default()
            };

            LookupOptions::for_dnssec(edns.dnssec_ok(), supported_algorithms)
        } else {
            LookupOptions::default()
        }
    }
}

async fn build_response(
    authority: &dyn AuthorityObject,
    request_info: RequestInfo<'_>,
    request_id: u16,
    request_header: &Header,
    query: &LowerQuery,
    edns: Option<&Edns>,
) -> (Header, LookupSections) {
    println!("{}, {}, {:?}", query.name(), query.name().is_fqdn(), query.name().labels());
    let lookup_options = lookup_options_for_edns(edns);

    // log algorithms being requested
    if lookup_options.is_dnssec() {
        info!(
            "request: {} lookup_options: {:?}",
            request_id, lookup_options
        );
    }

    let mut response_header = Header::response_from_request(request_header);
    response_header.set_authoritative(authority.zone_type().is_authoritative());

    debug!("performing {} on {}", query, authority.origin());
    let future = authority.search(request_info, lookup_options);

    #[allow(deprecated)]
    let sections = match authority.zone_type() {
        ZoneType::Primary | ZoneType::Secondary | ZoneType::Master | ZoneType::Slave => {
            send_authoritative_response(
                future,
                authority,
                &mut response_header,
                lookup_options,
                request_id,
                query,
            )
            .await
        }
        ZoneType::Forward | ZoneType::Hint => {
            send_forwarded_response(future, request_header, &mut response_header).await
        }
    };

    (response_header, sections)
}

async fn send_authoritative_response(
    future: impl Future<Output = Result<Box<dyn LookupObject>, LookupError>>,
    authority: &dyn AuthorityObject,
    response_header: &mut Header,
    lookup_options: LookupOptions,
    request_id: u16,
    query: &LowerQuery,
) -> LookupSections {
    // In this state we await the records, on success we transition to getting
    // NS records, which indicate an authoritative response.
    //
    // On Errors, the transition depends on the type of error.
    let answers = match future.await {
        Ok(records) => {
            response_header.set_response_code(ResponseCode::NoError);
            response_header.set_authoritative(true);
            Some(records)
        }
        // This request was refused
        // TODO: there are probably other error cases that should just drop through (FormErr, ServFail)
        Err(LookupError::ResponseCode(ResponseCode::Refused)) => {
            response_header.set_response_code(ResponseCode::Refused);
            return LookupSections {
                answers: Box::<AuthLookup>::default(),
                ns: Box::<AuthLookup>::default(),
                soa: Box::<AuthLookup>::default(),
                additionals: Box::<AuthLookup>::default(),
            };
        }
        Err(e) => {
            if e.is_nx_domain() {
                response_header.set_response_code(ResponseCode::NXDomain);
            } else if e.is_name_exists() {
                response_header.set_response_code(ResponseCode::NoError);
            };
            None
        }
    };

    let (ns, soa) = if answers.is_some() {
        // SOA queries should return the NS records as well.
        if query.query_type().is_soa() {
            // This was a successful authoritative lookup for SOA:
            //   get the NS records as well.
            match authority.ns(lookup_options).await {
                Ok(ns) => (Some(ns), None),
                Err(e) => {
                    warn!("ns_lookup errored: {}", e);
                    (None, None)
                }
            }
        } else {
            (None, None)
        }
    } else {
        let nsecs = if lookup_options.is_dnssec() {
            // in the dnssec case, nsec records should exist, we return NoError + NoData + NSec...
            debug!("request: {} non-existent adding nsecs", request_id);
            // run the nsec lookup future, and then transition to get soa
            let future = authority.get_nsec_records(query.name(), lookup_options);
            match future.await {
                // run the soa lookup
                Ok(nsecs) => Some(nsecs),
                Err(e) => {
                    warn!("failed to lookup nsecs: {}", e);
                    None
                }
            }
        } else {
            None
        };

        match authority.soa_secure(lookup_options).await {
            Ok(soa) => (nsecs, Some(soa)),
            Err(e) => {
                warn!("failed to lookup soa: {}", e);
                (nsecs, None)
            }
        }
    };

    // everything is done, return results.
    let (answers, additionals) = match answers {
        Some(mut answers) => match answers.take_additionals() {
            Some(additionals) => (answers, additionals),
            None => (
                answers,
                Box::<AuthLookup>::default() as Box<dyn LookupObject>,
            ),
        },
        None => (
            Box::<AuthLookup>::default() as Box<dyn LookupObject>,
            Box::<AuthLookup>::default() as Box<dyn LookupObject>,
        ),
    };

    let c = additionals.iter().count();
    println!("additional={}, response_code={}", c, response_header.response_code());
    if let Some(a) = additionals.iter().next() {
        println!("{:?}", a);
    }

    LookupSections {
        answers,
        ns: ns.unwrap_or_else(|| Box::<AuthLookup>::default()),
        soa: soa.unwrap_or_else(|| Box::<AuthLookup>::default()),
        additionals,
    }
}

async fn send_forwarded_response(
    future: impl Future<Output = Result<Box<dyn LookupObject>, LookupError>>,
    request_header: &Header,
    response_header: &mut Header,
) -> LookupSections {
    response_header.set_recursion_available(true);
    response_header.set_authoritative(false);

    // Don't perform the recursive query if this is disabled...
    let answers = if !request_header.recursion_desired() {
        // cancel the future??
        // future.cancel();
        drop(future);

        info!(
            "request disabled recursion, returning no records: {}",
            request_header.id()
        );

        Box::new(EmptyLookup)
    } else {
        match future.await {
            Err(e) => {
                if e.is_nx_domain() {
                    response_header.set_response_code(ResponseCode::NXDomain);
                }
                debug!("error resolving: {}", e);
                Box::new(EmptyLookup)
            }
            Ok(rsp) => rsp,
        }
    };

    LookupSections {
        answers,
        ns: Box::<AuthLookup>::default(),
        soa: Box::<AuthLookup>::default(),
        additionals: Box::<AuthLookup>::default(),
    }
}

struct LookupSections {
    answers: Box<dyn LookupObject>,
    ns: Box<dyn LookupObject>,
    soa: Box<dyn LookupObject>,
    additionals: Box<dyn LookupObject>,
}

// fn dump_dyn(authority: &dyn AuthorityObject, f: &mut Vec<u8>) {
//     // let size = std::mem::size_of::<&dyn AuthorityObject>();
//     let size = 8;
//     unsafe {
//         let some_bytes: &[u8] = std::slice::from_raw_parts(
//             &authority as *const &dyn AuthorityObject as *const u8,
//             size,
//         );
//         _ = write!(f, "\"%dyn_authority\": {{ \"data\": {:?}, \"__size__\": 8, \"__type__\": \"ptr\" }}, ", some_bytes);
// 
//         // let auth_ptr = u64::from_le_bytes(some_bytes[0..8].try_into().unwrap());
//         // if auth_ptr != 0 {
//         //     // let ptr = auth_ptr as *const u64;
//         //     // println!("\"{:p}\", {}", ptr, *ptr);
//         // }
//     }
// }

//   0                                                       32          336           352                                                                                                                           624        632  640                                                          696
// { %"core::option::Option<hickory_proto::op::edns::Edns>", [38 x i64], { ptr, ptr }, %"hickory_server::server::server_future::ReportingResponseHandler<hickory_server::server::response_handler::ResponseHandle>", [1 x i64], ptr, %"hickory_server::server::request_handler::RequestInfo<'_>", [1 x i8], i8, [1006 x i8] }
//  
//   0          32                                                      64                                                                                                                            336         696           704
// { [4 x i64], %"core::option::Option<hickory_proto::op::edns::Edns>", %"hickory_server::server::server_future::ReportingResponseHandler<hickory_server::server::response_handler::ResponseHandle>", [360 x i8], i8, [7 x i8], %"[async fn body@hickory_server::authority::catalog::send_response<'_, hickory_server::server::server_future::ReportingResponseHandler<hickory_server::server::response_handler::ResponseHandle>, alloc::boxed::Box<dyn core::iter::traits::iterator::Iterator<Item = &hickory_proto::rr::resource::Record> + core::marker::Send>, alloc::boxed::Box<dyn core::iter::traits::iterator::Iterator<Item = &hickory_proto::rr::resource::Record> + core::marker::Send>, alloc::boxed::Box<dyn core::iter::traits::iterator::Iterator<Item = &hickory_proto::rr::resource::Record> + core::marker::Send>, alloc::boxed::Box<dyn core::iter::traits::iterator::Iterator<Item = &hickory_proto::rr::resource::Record> + core::marker::Send>>::{closure#0}]", %"hickory_server::authority::catalog::LookupSections" }
// { [4 x i64], %"core::option::Option<hickory_proto::op::edns::Edns>", %"hickory_server::server::server_future::ReportingResponseHandler<hickory_server::server::response_handler::ResponseHandle>", [36 x i64], ptr, [9 x i64], %"[async fn body@hickory_server::authority::catalog::build_response::{closure#0}]" }
//   0          32                                                      64                                                                                                                            336         624  632        704
// 
//     0    8      16   24         32   40   48                                                           104  106        132 133
// { { ptr, ptr }, ptr, [1 x i64], ptr, ptr, %"hickory_server::server::request_handler::RequestInfo<'_>", i16, [26 x i8], i8, [147 x i8] }
// 
//   0          24   32          106  108                                   130 131 132       136
// { [3 x i64], ptr, [37 x i16], i16, %"hickory_proto::op::header::Header", i8, i8, [4 x i8], %"[async fn body@hickory_server::authority::catalog::send_authoritative_response<core::pin::Pin<alloc::boxed::Box<dyn core::future::future::Future<Output = core::result::Result<alloc::boxed::Box<dyn hickory_server::authority::authority_object::LookupObject>, hickory_server::authority::error::LookupError>> + core::marker::Send>>>::{closure#0}]" }
// { [3 x i64], ptr, [37 x i16], i16, %"hickory_proto::op::header::Header", i8, i8, [4 x i8], %"[async fn body@hickory_server::authority::catalog::send_forwarded_response<core::pin::Pin<alloc::boxed::Box<dyn core::future::future::Future<Output = core::result::Result<alloc::boxed::Box<dyn hickory_server::authority::authority_object::LookupObject>, hickory_server::authority::error::LookupError>> + core::marker::Send>>>::{closure#0}]" }
// 
// { [4 x i64], { ptr, ptr }, { ptr, ptr }, [2 x i64], ptr, ptr, i16, [5 x i8], i8, i8, [39 x i8] }
//
// %"core::option::Option<hickory_server::authority::auth_lookup::LookupRecords>" = type { [40 x i16], i16, [3 x i16] }
//
//                                                                                          0          56   64                                                           120
// %"[async block@crates/server/src/store/in_memory/authority.rs:1178:44: 1228:6]" = type { [7 x i64], ptr, %"hickory_server::server::request_handler::RequestInfo<'_>", [4 x i8], i8, i8, [794 x i8] }
// %"[async block@crates/server/src/store/in_memory/authority.rs:1178:44: 1228:6]::Suspend2" = type { %"hickory_server::server::request_handler::RequestInfo<'_>", [32 x i16], { i16, i16 }, [2 x i16], { ptr, ptr } }
// %"[async block@crates/server/src/store/in_memory/authority.rs:1178:44: 1228:6]::Suspend1" = type { %"hickory_server::server::request_handler::RequestInfo<'_>", [32 x i16], { i16, i16 }, [2 x i16], %"futures_util::future::try_future::MapOk<futures_util::future::try_join::TryJoin3<core::pin::Pin<alloc::boxed::Box<dyn core::future::future::Future<Output = core::result::Result<authority::auth_lookup::AuthLookup, authority::error::LookupError>> + core::marker::Send>>, core::pin::Pin<alloc::boxed::Box<dyn core::future::future::Future<Output = core::result::Result<authority::auth_lookup::AuthLookup, authority::error::LookupError>> + core::marker::Send>>, core::pin::Pin<alloc::boxed::Box<dyn core::future::future::Future<Output = core::result::Result<authority::auth_lookup::AuthLookup, authority::error::LookupError>> + core::marker::Send>>>, [closure@crates/server/src/store/in_memory/authority.rs:1214:25: 1214:56]>" }
//                                                                                                    0                                                            56          120           124        128
// { %"core::option::Option<hickory_proto::op::edns::Edns>", [40 x i64], %"hickory_server::server::server_future::ReportingResponseHandler<hickory_server::server::response_handler::ResponseHandle>", [19 x i64], %"hickory_server::authority::message_response::MessageResponse<'_, '_, alloc::boxed::Box<dyn core::iter::traits::iterator::Iterator<Item = &hickory_proto::rr::resource::Record> + core::marker::Send>, alloc::boxed::Box<dyn core::iter::traits::iterator::Iterator<Item = &hickory_proto::rr::resource::Record> + core::marker::Send>, alloc::boxed::Box<dyn core::iter::traits::iterator::Iterator<Item = &hickory_proto::rr::resource::Record> + core::marker::Send>, alloc::boxed::Box<dyn core::iter::traits::iterator::Iterator<Item = &hickory_proto::rr::resource::Record> + core::marker::Send>>", [2 x i8], i8, [5 x i8] }
//   0                                                       32          352