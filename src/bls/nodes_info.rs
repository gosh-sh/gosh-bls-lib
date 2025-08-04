use std::collections::HashMap;

use tvm_types::{fail, Result};

use std::time::Instant;

use crate::bls::gen_signer_indexes;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NodesInfo {
    pub map: HashMap<u16, u16>,
    pub total_num_of_nodes: u16,
}

impl NodesInfo {
    pub fn create_node_info(total_num_of_nodes: u16, node_index: u16) -> Result<Self> {
        if total_num_of_nodes == 0 {
            fail!("Total number of nodes can not be zero!");
        }
        if node_index >= total_num_of_nodes {
            fail!("Index of node can not be greater than total number of nodes!");
        }
        let mut info = HashMap::new();
        let num_of_occurrences = 1;
        info.insert(node_index, num_of_occurrences);
        Ok(Self {
            map: info,
            total_num_of_nodes,
        })
    }

    pub fn with_data(info: HashMap<u16, u16>, total_num_of_nodes: u16) -> Result<Self> {
        if total_num_of_nodes == 0 {
            fail!("Total number of nodes can not be zero!");
        }
        if info.is_empty() {
            fail!("Node info should not be empty!")
        }
        for (index, number_of_occurrence) in &info {
            if *index >= total_num_of_nodes {
                fail!("Index of node can not be greater than total number of nodes!")
            }
            if *number_of_occurrence == 0 {
                fail!("Number of occurrence for node can not be zero!")
            }
        }
        let nodes_info = NodesInfo {
            map: info,
            total_num_of_nodes,
        };
        Ok(nodes_info)
    }

    pub fn print(&self) {
        println!("--------------------------------------------------");
        println!("Total number of nodes: {}", &self.total_num_of_nodes);
        println!("Indexes -- occurrences: ");
        for (index, number_of_occurrence) in &self.map {
            println!("{}: \"{}\"", index, number_of_occurrence);
        }
        println!("--------------------------------------------------");
        println!("--------------------------------------------------");
    }

    pub fn merge(info1: &NodesInfo, info2: &NodesInfo) -> Result<NodesInfo> {
        if info1.total_num_of_nodes != info2.total_num_of_nodes {
            fail!("Total number of nodes must be the same!");
        }
        let mut new_info = info1.map.clone();
        for (index, number_of_occurrence) in &info2.map {
            new_info.insert(
                *index,
                if new_info.contains_key(index) {
                    new_info[index] + *number_of_occurrence
                } else {
                    *number_of_occurrence
                },
            );
        }
        Ok(NodesInfo {
            map: new_info,
            total_num_of_nodes: info1.total_num_of_nodes,
        })
    }

    pub fn merge_multiple(info_vec: &[&NodesInfo]) -> Result<NodesInfo> {
        if info_vec.len() <= 1 {
            fail!("Nodes info collection must have at least two elements!!")
        }
        let mut final_nodes_info = NodesInfo::merge(info_vec[0], info_vec[1])?;
        for item in info_vec.iter().skip(2) {
            final_nodes_info = NodesInfo::merge(&final_nodes_info, item)?;
        }
        Ok(final_nodes_info)
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut result_vec = Vec::new();
        let total_num_of_nodes = &self.total_num_of_nodes;
        let total_num_of_nodes_bytes = total_num_of_nodes.to_be_bytes();
        result_vec.extend_from_slice(&total_num_of_nodes_bytes);
        for (index, number_of_occurrence) in &self.map {
            let index_bytes = index.to_be_bytes();
            result_vec.extend_from_slice(&index_bytes);
            let number_of_occurrence_bytes = number_of_occurrence.to_be_bytes();
            result_vec.extend_from_slice(&number_of_occurrence_bytes);
        }
        result_vec
    }

    pub fn deserialize(info_bytes: &[u8]) -> Result<NodesInfo> {
        if info_bytes.len() <= 2 || (info_bytes.len() % 4) != 2 {
            fail!("node_info_bytes must have non zero length (> 2) being of form 4*k+2!");
        }
        let total_num_of_nodes = ((info_bytes[0] as u16) << 8) | info_bytes[1] as u16;
        if total_num_of_nodes == 0 {
            fail!("Total number of nodes can not be zero!");
        }
        let mut new_info = HashMap::new();
        for i in (2..info_bytes.len()).step_by(4) {
            let index = ((info_bytes[i] as u16) << 8) | info_bytes[i + 1] as u16;
            if index >= total_num_of_nodes {
                fail!("Index can not be greater than total_num_of_nodes!");
            }
            let number_of_occurrence = ((info_bytes[i + 2] as u16) << 8) | info_bytes[i + 3] as u16;
            new_info.insert(index, number_of_occurrence);
        }

        NodesInfo::with_data(new_info, total_num_of_nodes)
    }
}

fn merge_signatures_occurences(signatures_occurences_vec: &Vec<HashMap<u16, u16>>) -> Result<HashMap<u16, u16>> {
    if signatures_occurences_vec.len() == 0 {
        fail!("signatures_occurences empty");
    }
    if signatures_occurences_vec.len() == 1 {
        Ok(signatures_occurences_vec.get(0).unwrap().clone())
    }
    else {
        let now = Instant::now();

        let mut merged_signatures_occurences = signatures_occurences_vec.get(0).unwrap().clone();
        let duration = now.elapsed();
        println!("Clone time {:?}", duration);
        for incoming_signature_occurences in signatures_occurences_vec.iter().skip(1) {
            for signer_index in incoming_signature_occurences.keys() {
                let new_count = (*merged_signatures_occurences.get(signer_index).unwrap_or(&0))
                        + (*incoming_signature_occurences.get(signer_index).unwrap());
                merged_signatures_occurences.insert(*signer_index, new_count);
            }
        }
        //merged_signatures_occurences.retain(|_k, count| *count > 0);
        Ok(merged_signatures_occurences)
    }
} 

fn make_() -> HashMap<u16, u16> {
   let number_of_keys = 10000;
    //let number_of_signatures = 10000;
    let indexes: Vec<u16> = gen_signer_indexes(number_of_keys, 2 * number_of_keys);
    let mut nodes_info_vec = Vec::new();
    for ind in indexes {
        //println!("Node index = {}", ind);
        let mut nodes_info: HashMap<u16, u16> = HashMap::new();
        nodes_info.insert(ind, 1);
        nodes_info_vec.push(nodes_info);
    }
    let now = Instant::now();

    let mut nodes_info = merge_signatures_occurences(&nodes_info_vec).unwrap();
    let duration = now.elapsed();
    nodes_info
}

#[test]
fn test_() {
    //let number_of_keys = 10000;
    let number_of_signatures = 1000;
    let mut nodes_info_vec = Vec::new();
    for _i in 0..number_of_signatures {
        nodes_info_vec.push(make_());
    }
    let now = Instant::now();
    let mut nodes_info = merge_signatures_occurences(&nodes_info_vec).unwrap();
    let duration = now.elapsed();
    /*println!(
            "nodes_info: {:?}",
            nodes_info
    );*/
    println!(
            "Time elapsed by aggregate_bls_signatures is: {:?}",
            duration
    );
}

