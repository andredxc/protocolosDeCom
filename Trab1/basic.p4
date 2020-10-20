/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

#define MAX_HOPS 20

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header int_pai_t {
//    bit<32> Tamanho_Filho;
    bit<32> Quantidade_Filhos;
}

header int_filho_t {
  bit<32> ID_Switch;
  bit<9> Porta_Entrada;
  bit<9> Porta_Saida;
  bit<48> Timestamp;
  bit<6> padding;
}

struct metadata {
    bit<32> nRemaining;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    int_pai_t    intPai;
    int_filho_t[MAX_HOPS] intFilho;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.flags) {
            1 : parse_intPai;
            3 : parse_intPai;
            5 : parse_intPai;
            7 : parse_intPai;
            default : accept;
        }
    }

    state parse_intPai {
        packet.extract(hdr.intPai);
        meta.nRemaining = hdr.intPai.Quantidade_Filhos;
        transition select(hdr.intPai.Quantidade_Filhos) {
            0       : accept;
            default : parse_intFilho;
        }
    }

    state parse_intFilho {
        packet.extract(hdr.intFilho.next);
        meta.nRemaining = meta.nRemaining - 1;
        transition select(meta.nRemaining) {
            0 : accept;
            default: parse_intFilho;
        }
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop();
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action new_intPai() {
        hdr.intPai.setValid();
        hdr.intPai.Quantidade_Filhos = 0;
    }

    action new_intFilho() {
        hdr.intPai.Quantidade_Filhos = hdr.intPai.Quantidade_Filhos + 1;
        hdr.intFilho.push_front(1);
        hdr.intFilho[0].setValid();
        hdr.intFilho[0].Porta_Entrada = standard_metadata.ingress_port;
        hdr.intFilho[0].Porta_Saida   = standard_metadata.egress_spec;
        hdr.intFilho[0].ID_Switch     = 0x0;//NAO SEI
        hdr.intFilho[0].Timestamp     = 0x0;//intrinsic_metadata.ingress_global_timestamp;
            // https://github.com/p4lang/behavioral-model/blob/master/docs/simple_switch.md
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.ipv4.flags == 1 || hdr.ipv4.flags == 3 || hdr.ipv4.flags == 5 || hdr.ipv4.flags == 7) {
            if (hdr.intPai.isValid()) {
                new_intFilho();
                if (hdr.ipv4.isValid()) {
                    ipv4_lpm.apply();
                }
            }
            else {
                drop();
            }
        } 
        else {
            hdr.ipv4.flags = 1;
            new_intPai();
            new_intFilho();
            if (hdr.ipv4.isValid()) {
                    ipv4_lpm.apply();
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.intPai);
        packet.emit(hdr.intFilho);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
