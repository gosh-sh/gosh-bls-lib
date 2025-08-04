use super::converters::*;

use super::nodes_info::*;

use blst::min_pk::PublicKey;
use blst::min_pk::Signature;
use blst::*;

//use blst::min_sig::*;

use tvm_types::{fail, Result};

use crate::bls::BLS_SECRET_KEY_LEN;
use crate::bls::{add_node_info_to_sig, BLS_PUBLIC_KEY_LEN, BLS_SIG_LEN};

pub const DST: [u8; 43] = *b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BlsSignature {
    pub sig_bytes: [u8; BLS_SIG_LEN],
    pub nodes_info: NodesInfo,
}

impl BlsSignature {
    pub fn serialize(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend_from_slice(&self.sig_bytes);
        let nodes_info_bytes = &self.nodes_info.serialize();
        vec.extend_from_slice(nodes_info_bytes);
        vec
    }

    pub fn deserialize(sig_bytes_with_nodes_info: &[u8]) -> Result<Self> {
        if sig_bytes_with_nodes_info.len() < BLS_SIG_LEN + 6 {
            fail!("Length of sig_bytes_with_nodes_info is too short!")
        }
        let mut sig_bytes: [u8; BLS_SIG_LEN] = [0; BLS_SIG_LEN];
        sig_bytes.copy_from_slice(&sig_bytes_with_nodes_info[0..BLS_SIG_LEN]);
        let len = sig_bytes_with_nodes_info.len() - BLS_SIG_LEN;
        let mut nodes_info_data = vec![0; len];
        nodes_info_data.copy_from_slice(&sig_bytes_with_nodes_info[BLS_SIG_LEN..]);
        let nodes_info = NodesInfo::deserialize(&nodes_info_data)?;
        Ok(Self {
            sig_bytes,
            nodes_info,
        })
    }

    pub fn simple_sign(
        sk_bytes: &[u8; BLS_SECRET_KEY_LEN],
        msg: &[u8],
    ) -> Result<[u8; BLS_SIG_LEN]> {
        if msg.is_empty() {
            fail!("Msg to sign can not be empty!")
        }
        let sk = convert_secret_key_bytes_to_secret_key(sk_bytes)?;
        let sig = sk.sign(msg, &DST, &[]);
        Ok(sig.to_bytes())
    }

    pub fn validate_signature(
        sig_bytes: &[u8; BLS_SIG_LEN],
    ) -> bool {
        match Signature::sig_validate(sig_bytes, false) {
            Ok(_) => true,
            Err(err) => false
        } 
    }


    pub fn simple_verify(
        sig_bytes: &[u8; BLS_SIG_LEN],
        msg: &[u8],
        pk_bytes: &[u8; BLS_PUBLIC_KEY_LEN],
    ) -> Result<bool> {
        if msg.is_empty() {
            fail!("Msg to sign can not be empty!")
        }
        let sig = convert_signature_bytes_to_signature(sig_bytes)?;
        let pk = convert_public_key_bytes_to_public_key(pk_bytes)?;
        let res = sig.verify(true, msg, &DST, &[], &pk, true);
        Ok(res == BLST_ERROR::BLST_SUCCESS)
    }

    pub fn add_node_info_to_sig(
        sig_bytes: [u8; BLS_SIG_LEN],
        node_index: u16,
        total_num_of_nodes: u16,
    ) -> Result<Vec<u8>> {
        if total_num_of_nodes == 0 {
            fail!("Total number of nodes can not be zero!");
        }
        if node_index >= total_num_of_nodes {
            fail!("Index of node can not be greater than total number of nodes!");
        }
        let nodes_info = NodesInfo::create_node_info(total_num_of_nodes, node_index)?;
        let sig = Self {
            sig_bytes,
            nodes_info,
        };
        let sig_bytes = BlsSignature::serialize(&sig);
        Ok(sig_bytes)
    }

    pub fn sign(
        sk_bytes: &[u8; BLS_SECRET_KEY_LEN],
        msg: &[u8],
        node_index: u16,
        total_num_of_nodes: u16,
    ) -> Result<Vec<u8>> {
        let sig = BlsSignature::simple_sign(sk_bytes, msg)?;
        add_node_info_to_sig(sig, node_index, total_num_of_nodes)
    }

    pub fn get_nodes_info_from_sig(sig_bytes_with_nodes_info: &[u8]) -> Result<Vec<u8>> {
        let bls_sig = BlsSignature::deserialize(sig_bytes_with_nodes_info)?;
        Ok(bls_sig.nodes_info.serialize())
    }

    pub fn truncate_nodes_info_from_sig(
        sig_bytes_with_nodes_info: &[u8],
    ) -> Result<[u8; BLS_SIG_LEN]> {
        let bls_sig = BlsSignature::deserialize(sig_bytes_with_nodes_info)?;
        Ok(bls_sig.sig_bytes)
    }

    pub fn verify(
        sig_bytes_with_nodes_info: &[u8],
        pk_bytes: &[u8; BLS_PUBLIC_KEY_LEN],
        msg: &[u8],
    ) -> Result<bool> {
        let sig_bytes = BlsSignature::truncate_nodes_info_from_sig(sig_bytes_with_nodes_info)?;
        let res = BlsSignature::simple_verify(&sig_bytes, msg, pk_bytes)?;
        Ok(res)
    }

    pub fn validate_public_key(
        pk_bytes: &[u8; BLS_PUBLIC_KEY_LEN],
    ) -> bool {
        match PublicKey::key_validate(pk_bytes) {
            Ok(_) => true,
            Err(err) => false
        }
        
    }

    pub fn print_signature_bytes(sig_bytes: &[u8]) {
        if sig_bytes.len() != BLS_SIG_LEN {
            panic!("Incorrect length of signature byte array!")
        }
        println!("--------------------------------------------------");
        println!("BLS Signature bytes:");
        println!("--------------------------------------------------");
        println!("{:?}", sig_bytes);
        println!("--------------------------------------------------");
    }

    pub fn print_bls_signature(bls_sig_bytes: &[u8]) {
        let bls_sig = BlsSignature::deserialize(bls_sig_bytes).unwrap();
        bls_sig.print();
    }

    pub fn print(&self) {
        println!("--------------------------------------------------");
        println!("Aggregated BLS signature:");
        println!("--------------------------------------------------");
        println!("Signature bytes:");
        println!("{:?}", &self.sig_bytes);
        self.nodes_info.print();
        println!("--------------------------------------------------");
    }
}
