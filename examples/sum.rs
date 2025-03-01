// SPDX-License-Identifier: MPL-2.0

use prio::client::*;
use prio::field::*;
use prio::server::*;

fn main() {
    let dim = 8;

    let mut client1 = Client::new(dim).unwrap();
    let mut client2 = Client::new(dim).unwrap();

    let data1_u32 = [0, 0, 1, 1, 1, 0, 0, 0];
    println!("Client 1 Input: {:?}", data1_u32);

    let data1 = data1_u32
        .iter()
        .map(|x| Field32::from(*x))
        .collect::<Vec<Field32>>();

    let data2_u32 = [0, 0, 1, 0, 1, 0, 0, 0];
    println!("Client 2 Input: {:?}", data2_u32);

    let data2 = data2_u32
        .iter()
        .map(|x| Field32::from(*x))
        .collect::<Vec<Field32>>();

    let (share1_1, share1_2) = client1.encode_simple(&data1).unwrap();
    let (share2_1, share2_2) = client2.encode_simple(&data2).unwrap();
    let eval_at = Field32::from(12313);

    println!("share1_1: {:?}", &share1_1);
    println!("encoded share1_1: {:?}", base64::encode(&share1_1));
    println!("share1_2: {:?}", &share1_1);
    println!("encoded share1_2: {:?}", base64::encode(&share1_2));

    let mut server1: Server<Field32> = Server::new(dim, true).unwrap();
    let mut server2 = Server::new(dim, false).unwrap();

    let v1_1 = server1
        .generate_verification_message(eval_at, &share1_1)
        .unwrap();
    let v1_2 = server2
        .generate_verification_message(eval_at, &share1_2)
        .unwrap();

    let v2_1 = server1
        .generate_verification_message(eval_at, &share2_1)
        .unwrap();
    let v2_2 = server2
        .generate_verification_message(eval_at, &share2_2)
        .unwrap();

    let v1_1_string = serde_json::to_string(&v1_1).unwrap();
    println!("v1_1_string: {:?}", v1_1_string);
    let v1_2_string = serde_json::to_string(&v1_2).unwrap();
    println!("v1_2_string: {:?}", v1_2_string);

    let _ = server1.aggregate(&share1_1, &v1_1, &v1_2).unwrap();
    let _ = server2.aggregate(&share1_2, &v1_1, &v1_2).unwrap();

    let _ = server1.aggregate(&share2_1, &v2_1, &v2_2).unwrap();
    let _ = server2.aggregate(&share2_2, &v2_1, &v2_2).unwrap();

    server1.merge_total_shares(server2.total_shares()).unwrap();
    println!("Final Publication: {:?}", server1.total_shares());
}
