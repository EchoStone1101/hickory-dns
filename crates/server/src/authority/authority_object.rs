// Copyright 2015-2021 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! All authority related types

use std::sync::Arc;

use dump::Walk;
use tracing::debug;

use crate::{
    authority::{Authority, LookupError, LookupOptions, MessageRequest, UpdateResult, ZoneType},
    proto::rr::{LowerName, Record, RecordType},
    server::RequestInfo,
};

/// An Object safe Authority
#[async_trait::async_trait]
pub trait AuthorityObject: Send + Sync + Walk {
    /* Vtable of FileAuthority
    @vtable.h = private unnamed_addr constant <{ ptr, [16 x i8], ptr, ptr, ptr, ptr, ptr, ptr, ptr, ptr, ptr, ptr, ptr, ptr }> 
    0: <{ ptr @"_ZN4core3ptr98drop_in_place$LT$alloc..sync..Arc$LT$hickory_server..store..file..authority..FileAuthority$GT$$GT$17hddfaab638e079395E", 
    1,2:[16 x i8] c"\08\00\00\00\00\00\00\00\08\00\00\00\00\00\00\00", 
    3:ptr @alloc_2e1af0b5b30dc9c02b22fc21e263cc1e, 
    4:ptr @"_ZN106_$LT$alloc..sync..Arc$LT$A$GT$$u20$as$u20$hickory_server..authority..authority_object..AuthorityObject$GT$9box_clone17h155272cdf0029148E", 
    5:ptr @"_ZN106_$LT$alloc..sync..Arc$LT$A$GT$$u20$as$u20$hickory_server..authority..authority_object..AuthorityObject$GT$9zone_type17h48a0ff3b79382badE", 
    6:ptr @"_ZN106_$LT$alloc..sync..Arc$LT$A$GT$$u20$as$u20$hickory_server..authority..authority_object..AuthorityObject$GT$15is_axfr_allowed17h20c6fbc91e006d3cE", 
    7:ptr @"_ZN106_$LT$alloc..sync..Arc$LT$A$GT$$u20$as$u20$hickory_server..authority..authority_object..AuthorityObject$GT$6update17h38a73f6c3822cd66E", 
    8:ptr @"_ZN106_$LT$alloc..sync..Arc$LT$A$GT$$u20$as$u20$hickory_server..authority..authority_object..AuthorityObject$GT$6origin17h81d4f9358ad5de8cE", 
    9:ptr @"_ZN106_$LT$alloc..sync..Arc$LT$A$GT$$u20$as$u20$hickory_server..authority..authority_object..AuthorityObject$GT$6lookup17h189f6015565959beE", 
    10:ptr @"_ZN106_$LT$alloc..sync..Arc$LT$A$GT$$u20$as$u20$hickory_server..authority..authority_object..AuthorityObject$GT$6search17h83dbee6999bfc45aE", 
    11:ptr @_ZN14hickory_server9authority16authority_object15AuthorityObject2ns17h25231631e0e4d049E, 
    12:ptr @"_ZN106_$LT$alloc..sync..Arc$LT$A$GT$$u20$as$u20$hickory_server..authority..authority_object..AuthorityObject$GT$16get_nsec_records17h578e759b0658dafcE", 
    13:ptr @_ZN14hickory_server9authority16authority_object15AuthorityObject3soa17hf7f8be329c7893e2E, 
    14:ptr @_ZN14hickory_server9authority16authority_object15AuthorityObject10soa_secure17h7f3bbcf126065f23E }>, align 8
    */

    /// Dump function for trait object.
    fn dump(&self, f: &mut Vec<u8>);

    /// Clone the object
    fn box_clone(&self) -> Box<dyn AuthorityObject>;

    /// What type is this zone
    fn zone_type(&self) -> ZoneType;

    /// Return true if AXFR is allowed
    fn is_axfr_allowed(&self) -> bool;

    /// Perform a dynamic update of a zone
    async fn update(&self, update: &MessageRequest) -> UpdateResult<bool>;

    /// Get the origin of this zone, i.e. example.com is the origin for www.example.com
    fn origin(&self) -> &LowerName;

    /// Looks up all Resource Records matching the giving `Name` and `RecordType`.
    ///
    /// # Arguments
    ///
    /// * `name` - The `Name`, label, to lookup.
    /// * `rtype` - The `RecordType`, to lookup. `RecordType::ANY` will return all records matching
    ///             `name`. `RecordType::AXFR` will return all record types except `RecordType::SOA`
    ///             due to the requirements that on zone transfers the `RecordType::SOA` must both
    ///             precede and follow all other records.
    /// * `is_secure` - If the DO bit is set on the EDNS OPT record, then return RRSIGs as well.
    ///
    /// # Return value
    ///
    /// None if there are no matching records, otherwise a `Vec` containing the found records.
    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        lookup_options: LookupOptions,
    ) -> Result<Box<dyn LookupObject>, LookupError>;

    /// Using the specified query, perform a lookup against this zone.
    ///
    /// # Arguments
    ///
    /// * `query` - the query to perform the lookup with.
    /// * `is_secure` - if true, then RRSIG records (if this is a secure zone) will be returned.
    ///
    /// # Return value
    ///
    /// Returns a vector containing the results of the query, it will be empty if not found. If
    ///  `is_secure` is true, in the case of no records found then NSEC records will be returned.
    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> Result<Box<dyn LookupObject>, LookupError>;

    /// Get the NS, NameServer, record for the zone
    async fn ns(
        &self,
        lookup_options: LookupOptions,
    ) -> Result<Box<dyn LookupObject>, LookupError> {
        self.lookup(self.origin(), RecordType::NS, lookup_options)
            .await
    }

    /// Return the NSEC records based on the given name
    ///
    /// # Arguments
    ///
    /// * `name` - given this name (i.e. the lookup name), return the NSEC record that is less than
    ///            this
    /// * `is_secure` - if true then it will return RRSIG records as well
    async fn get_nsec_records(
        &self,
        name: &LowerName,
        lookup_options: LookupOptions,
    ) -> Result<Box<dyn LookupObject>, LookupError>;

    /// Returns the SOA of the authority.
    ///
    /// *Note*: This will only return the SOA, if this is fulfilling a request, a standard lookup
    ///  should be used, see `soa_secure()`, which will optionally return RRSIGs.
    async fn soa(&self) -> Result<Box<dyn LookupObject>, LookupError> {
        // SOA should be origin|SOA
        self.lookup(self.origin(), RecordType::SOA, LookupOptions::default())
            .await
    }

    /// Returns the SOA record for the zone
    async fn soa_secure(
        &self,
        lookup_options: LookupOptions,
    ) -> Result<Box<dyn LookupObject>, LookupError> {
        self.lookup(self.origin(), RecordType::SOA, lookup_options)
            .await
    }
}

#[async_trait::async_trait]
impl<A, L> AuthorityObject for Arc<A>
where
    A: Authority<Lookup = L> + Send + Sync + 'static + Walk,
    L: LookupObject + Send + Sync + 'static,
{
    fn dump(&self, f: &mut Vec<u8>) {
        use std::io::Write;
        let size = std::mem::size_of::<Arc<A>>();
        unsafe {
            let some_bytes: &[u8] = std::slice::from_raw_parts(
                self as *const Arc<A> as *const u8,
                size
            );
            _ = write!(f, "\"{:p}\": {{ \"data\": {:?}, \"__size__\": {}, \"__type__\": \"ptr\" }}, ", self, some_bytes, size);
        }
    }

    fn box_clone(&self) -> Box<dyn AuthorityObject> {
        Box::new(self.clone())
    }

    /// What type is this zone
    fn zone_type(&self) -> ZoneType {
        Authority::zone_type(self.as_ref())
    }

    /// Return true if AXFR is allowed
    fn is_axfr_allowed(&self) -> bool {
        Authority::is_axfr_allowed(self.as_ref())
    }

    /// Perform a dynamic update of a zone
    async fn update(&self, update: &MessageRequest) -> UpdateResult<bool> {
        Authority::update(self.as_ref(), update).await
    }

    /// Get the origin of this zone, i.e. example.com is the origin for www.example.com
    fn origin(&self) -> &LowerName {
        Authority::origin(self.as_ref())
    }

    /// Looks up all Resource Records matching the giving `Name` and `RecordType`.
    ///
    /// # Arguments
    ///
    /// * `name` - The `Name`, label, to lookup.
    /// * `rtype` - The `RecordType`, to lookup. `RecordType::ANY` will return all records matching
    ///             `name`. `RecordType::AXFR` will return all record types except `RecordType::SOA`
    ///             due to the requirements that on zone transfers the `RecordType::SOA` must both
    ///             precede and follow all other records.
    /// * `is_secure` - If the DO bit is set on the EDNS OPT record, then return RRSIGs as well.
    ///
    /// # Return value
    ///
    /// None if there are no matching records, otherwise a `Vec` containing the found records.
    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        lookup_options: LookupOptions,
    ) -> Result<Box<dyn LookupObject>, LookupError> {
        let this = self.as_ref();
        let lookup = Authority::lookup(this, name, rtype, lookup_options).await;
        lookup.map(|l| Box::new(l) as Box<dyn LookupObject>)
    }

    /// Using the specified query, perform a lookup against this zone.
    ///
    /// # Arguments
    ///
    /// * `query` - the query to perform the lookup with.
    /// * `is_secure` - if true, then RRSIG records (if this is a secure zone) will be returned.
    ///
    /// # Return value
    ///
    /// Returns a vector containing the results of the query, it will be empty if not found. If
    ///  `is_secure` is true, in the case of no records found then NSEC records will be returned.
    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> Result<Box<dyn LookupObject>, LookupError> {
        let this = self.as_ref();
        debug!("performing {} on {}", request_info.query, this.origin());
        let lookup = Authority::search(this, request_info, lookup_options).await;
        lookup.map(|l| Box::new(l) as Box<dyn LookupObject>)
    }

    /// Return the NSEC records based on the given name
    ///
    /// # Arguments
    ///
    /// * `name` - given this name (i.e. the lookup name), return the NSEC record that is less than
    ///            this
    /// * `is_secure` - if true then it will return RRSIG records as well
    async fn get_nsec_records(
        &self,
        name: &LowerName,
        lookup_options: LookupOptions,
    ) -> Result<Box<dyn LookupObject>, LookupError> {
        let lookup = Authority::get_nsec_records(self.as_ref(), name, lookup_options).await;
        lookup.map(|l| Box::new(l) as Box<dyn LookupObject>)
    }
}

/// An Object Safe Lookup for Authority
pub trait LookupObject: Send {
    /// Returns true if either the associated Records are empty, or this is a NameExists or NxDomain
    fn is_empty(&self) -> bool;

    /// Conversion to an iterator
    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Record> + Send + 'a>;

    /// For CNAME and similar records, this is an additional set of lookup records
    ///
    /// it is acceptable for this to return None after the first call.
    fn take_additionals(&mut self) -> Option<Box<dyn LookupObject>>;
}

/// A lookup that returns no records
#[derive(Clone, Copy, Debug)]
pub struct EmptyLookup;

impl LookupObject for EmptyLookup {
    fn is_empty(&self) -> bool {
        true
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Record> + Send + 'a> {
        Box::new([].iter())
    }

    fn take_additionals(&mut self) -> Option<Box<dyn LookupObject>> {
        None
    }
}
