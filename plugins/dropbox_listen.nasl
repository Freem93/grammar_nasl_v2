#TRUSTED 4beb3ad19d5c29e552e51057fba5f66ec5b525067d4a4adb20b25b92dca4dadc757b6a60f88f9998e8b59a30d4c958349bd93313b4536c84bb2c2d0a46f186502d47601c26b05daa95ffc56d7582019e18e2427a2a9a2962d99acf2a7d1c9f188a1ae5a5372c0694ef904484256a248b083899017fb000bbf6e2da070d7effb4eb202f02d05656f7c52f4395b704e45e8ebb7404a31984c4e3e5a34e154be0600f61003efce584dd9fe25174c3426d035d4f6f50159e4db399460b0c89e7b6d14dd2573a2d33f7a99de721912d395ffe9506faec20cc6d575bd1e77628d634fc98de416c9ae335eb19314f31b23a5af8cf5a7b51aa0a9e03b1b73ed454e3e64ca3fcabf4af1c1c8c12c135a5a0080fb4e9cf1a1a7ad4b4f241d47476e3f494ce5c23dfaf4edf2556f9627e83c6f6f40907e0fcf21251c6495546ce17590c37fd846d00a127f94f106644820230db2a4bdbd36bd462184da5c78561351d8b58c89a106e4b5b33f825a93dd48b435907524a42fc118664abfd79c53c367c9185cff440cf63e0dcb940e6636f65463250c7447cbffe868cbab4cec1622352b9b9f2db1cfadb5b03d7d92c762bea6ea4e2457ab197543320cf019e0ec70641390ec9f7a7ae87ece65ee3a69d6e9bcd92a04d5498fc519568de98f5c42b4077f85e3de784639f48f5f1eac44abecd8f04666a8321347066baaf5c1fa2caf36047139f
#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 4400 ) exit(1, "'bpf_open()' first appeared in Nessus 4.4.0.");

include("compat.inc");

if (description)
{
  script_id(56692);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2011/11/02");

  script_name(english:"Dropbox Software Detection (listener)");
  script_summary(english:"Listens for Dropbox broadcast messages");

  script_set_attribute(attribute:"synopsis",value:
"There is a file synchronization application on the remote host.");
  script_set_attribute(attribute:"description",value:
"Dropbox is installed on the remote host.  Dropbox is an application
for storing and synchronizing files between computers, possibly
outside the organization.");
  script_set_attribute(attribute:"see_also",value:"https://www.dropbox.com/");
  script_set_attribute(attribute:"solution", value:
"Ensure that use of this software agrees with your organization's
acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dropbox:dropbox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2011 Tenable Network Security, Inc.");
  exit(0);
}


include('raw.inc');

if (islocalhost()) exit(0, "This plugin can not be run against the localhost.");
if (!islocalnet()) exit(0, "The remote host is more than one hop away.");

mutex_lock(SCRIPT_NAME);
if ( get_global_kb_item("Dropbox/detection") )
{
 mutex_unlock(SCRIPT_NAME);
 exit(0);
}

ll = link_layer();
if ( isnull(ll) ) exit(1, "Could not find the link layer we are operating on.");

bpf = bpf_open("udp and src port 17500 and dst port 17500 and dst host 255.255.255.255");
if ( ! bpf ) exit(1, "Could not obtain a bpf.");
deadline = unixtime() + 35;
Results = make_array();
MAX_WAIT = 35000;
count = 0;
while ( unixtime() < deadline )
{
 if ( cnt >= 10000 ) break; # In case something broadcasts too many messages

 if ( (deadline - unixtime()) * 1000  < MAX_WAIT )
	MAX_WAIT = (deadline - unixtime()) * 1000;

 res = bpf_next(bpf:bpf, timeout:MAX_WAIT); 
 if ( res )
 {
  res = substr(res, strlen(ll), strlen(res) - 1);
  pkt = packet_split(res);
  ip_src = mkdword((pkt[0]['data']['ip_src']));
  ip_src = strcat(getbyte(blob:ip_src, pos:0), ".", getbyte(blob:ip_src, pos:1), ".", getbyte(blob:ip_src, pos:2), ".",getbyte(blob:ip_src, pos:3));
  data = pkt[2]['data'];
  if ( data && "host_int" >< data )
  {
   if ( isnull(Results[ip_src]) ) cnt ++;
   Results[ip_src] = data; 
  }
 }
}


set_global_kb_item(name:"Dropbox/detection", value:TRUE);
mutex_unlock(SCRIPT_NAME);

foreach host (keys(Results))
 set_global_kb_item(name:strcat("Dropbox/", host), value:Results[host]);
