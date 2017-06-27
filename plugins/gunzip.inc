#TRUSTED 5b852bd72e24450738f49657fe67442d09f39ef833de7a693116cf631d953b1b494828c1b360e95f5632e63b1d603be1e1c763aa3409176a3d01a4439f16b3afa5d852d084f0dd0f950b615701ee64991bd1ddd54cf92b01b412460c8254122dd37146c27c6b0a74ea3afc4944f34c251ae83f5f384c484e56b825733b4c4ada6b5e9e36d590df35ccb6e33767287e8522d6b5b1e332ccba1115443477e0294208a2e73894ce8b94419ab7061b73137ba1d8af6a8b9a82c693e178eae5a6debc5d4db5ef7ecc8f9610116a271e595d71d64dc381db5f77e1f76ac76e71588b39212eca937c10fa2f1313cf711b1979cf37c70b4881158eafc168825e53778b6b03b80b3e9768bec3cd22b7beecf064c47a1e390d7bb6d5e6f07bbc29abac7fbd70167440b22e0d6f7440068b7598054ef3e88c952add415bae98303da222b8796b3982c69e06e9bdc718c2fd9e3556794df0e08fbd11d01dfd7c373cb7115fb68ab627263fd802b5d599bd4642efb6a28fe38a19914bf50a93e91b889112231b3b2ec3c1719a1572535b57397b10ca04c017d7ade4ba0cdb3b23854094b72cd92c6a356b974bf1fc3d675cb17d2de06ceeeca0b6c62909f5fab8fab51d776dd59770d45e7e1381f5a36801d254a5f8ac6515a27402dbd65ea82af7567df33f216f5659a0bb6ee82aa25f307d3ccfcb7607dc0515338a26531d2f7dade74b0748
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# gunzip.inc
# Revision: 1.3
#


function gzip_parse_header()
{
 local_var buf;
 local_var h;
 local_var pos;
 local_var isize;
 
 set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

 buf = _FCT_ANON_ARGS[0];

 if ( strlen(buf) < 18 ) return NULL;

 h = make_array();
 h["id1"] = substr(buf, 0, 0);
 h["id2"] = substr(buf, 1, 1);
 if ( ord(h["id1"]) != 0x1f || ord(h["id2"]) != 0x8b ) return NULL;
 h["cm"] = substr(buf, 2, 2);
 h["flag"] = substr(buf, 3, 3);
 h["mtime"] = getdword(blob:buf, pos:4);
 h["xfl"]  = substr(buf, 8, 8);
 h["os"] = substr(buf, 9, 9);
 pos = 10;

 if ( ord(h["flag"]) & 4 )
 {
  # Untested
  h["xlen"] = getword(blob:buf, pos:pos); pos += 2;
  pos += h["xlen"];
 }

 if ( ord(h["flag"]) & 8 )
 {
  while ( ord(buf[pos]) != 0 ) pos ++;
  pos ++;
 }

 if ( ord(h["flag"]) & 16 )
 {
  while ( ord(buf[pos]) != 0 ) pos ++;
  pos ++;
 }

 if ( ord(h["flag"]) & 2 )
  pos += 2;

 h["crc32"] = getdword(blob:buf, pos:strlen(buf) - 8);
 h["isize"] = getdword(blob:buf, pos:strlen(buf) - 4);
 h["pos"] = pos;
 return h;
}

global_var _max_gunzip_size;
_max_gunzip_size = 1024 * 1024 * 40;

function set_max_gunzip_size()
{
  local_var size;
  size = int(_FCT_ANON_ARGS[0]);
  if (size <= 0)
    return;

  _max_gunzip_size = size;
}

function get_max_gunzip_size()
{
  return _max_gunzip_size;
}

function gunzip()
{
 local_var header;
 local_var data;

 data = _FCT_ANON_ARGS[0];
 header = gzip_parse_header(data);
 if ( isnull(header) ) return NULL;

 # workaround for VULN-81472
 if (header["isize"] >= get_max_gunzip_size()) return NULL;
 
 return zlib_decompress(data:substr(data, header["pos"], strlen(data) - 8), length:header["isize"]);
}

