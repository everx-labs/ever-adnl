/*
* Copyright (C) 2019-2023 EverX. All Rights Reserved.
*
* Licensed under the SOFTWARE EVALUATION License (the "License"); you may not use
* this file except in compliance with the License.
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific EVERX DEV software governing permissions and
* limitations under the License.
*/

// TO REMOVE AFTER FULL REBRANDING
extern crate ton_api as ever_api;

use adnl::common::Version;
use ever_api::{
    deserialize_boxed, IntoBoxed, 
    ton::{ //ever::{
        TLObject,
        rldp::{Message as RldpMessage, message::Query as RldpQuery},
        rpc::{ton_node/*ever_node*/::DownloadBlock, overlay::Query as OverlayQuery}
    }
};
use ever_block::UInt256;

fn print_tl_object(answer : TLObject) {
    if answer.is::<RldpMessage>() {
        let answer = answer.downcast::<RldpMessage>().unwrap();
        println!("{:?}", answer);
        let data = &answer.data();
        println!("{:?}", hex::encode(data));
    } else if answer.is::<OverlayQuery>() {
        println!("{:?}", answer.downcast::<OverlayQuery>().unwrap());
    } else if answer.is::<DownloadBlock>() {
        println!("{:?}", answer.downcast::<DownloadBlock>().unwrap());
    } else {
        println!("{:?}", answer);
    }
}

#[test]
fn test_decode() {

    let query_msg_str = 
        "4384fdccdc7c6d60991db081780e7e12627d8c315dc171db982452e91f1f30d738cef966c37972e2ffffffff\
         000000000000008097920a00bc8f430b9ae5817be1fa1974918df336dbc5678088e6ebbb9f6cb027ad0ea24b\
         f88dafbafb920d0feb50d4ca8241d920c48eaf63cb20924961ffd6f39966cb4d";

    let query_msg = hex::decode(query_msg_str).unwrap();
    let query1 = deserialize_boxed(query_msg).unwrap();
    print_tl_object(query1);
    // let query2 = deserializer.read_boxed().unwrap();   
    // print_tl_object(query2);
    
    let now = Version::get();
    let data = hex::decode(
        "4384fdccdc7c6d60991db081780e7e12627d8c315dc171db982452e91f1f30d738cef966c37972e2ffffffff\
         000000000000008097920a00bc8f430b9ae5817be1fa1974918df336dbc5678088e6ebbb9f6cb027ad0ea24b\
         f88dafbafb920d0feb50d4ca8241d920c48eaf63cb20924961ffd6f39966cb4d"
    ).unwrap();
    
    let q = RldpQuery { 
        query_id: UInt256::with_array([12;32]),
        max_answer_size: 4194304,
        timeout: now + 3600,
        data: data.into()
    }.into_boxed();
    println!("{:?}", q);

}

