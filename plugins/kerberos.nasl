#TRUSTED 571039491e51e59151d16282ef6bef7de4296da69fad90ef4a1c61791b0e9f7088b48fbe6a07cb087676d639d7f040626c9a937daf2a30da5e4b77b7df67c976ced458c4c54802bb18165b9ba8559982a02efae67ce087047da7c14915fdec1bdaa061ce77b2dcbb84fb4b4a74e49dec61d8ed2b700f591920565418e237c90b558a1fbea741c14be1f6025f32fa3b1ffd8e390f7891fdb285600dd682f0256126e5f49c7ad7b6f1ea9b3d1f620a4f0ea1aec71e78e8f17ecfc6ee58279f2532e9bbc12b74ffeadbe92581194e054f39dbe30d0a0251a16422ad12bc261b3b4f86e328c02aca3c9becfff0b72c8aafee1fbf59f7f6bf877ad0e44af9a395280972bfe6ea6821c4fe249771b0c92344cc9d81db595947db8c70f26c198d75f4c41813eddb53a69581424405c82baa401e6d163dcab5e58641db4d3748a6055a2a8c61edbbcbc59ba87405cc3356045571cb8bf255f84d56df6635b66ea054fbd07acb89c31277ee92243716ff8d2163b16715eb2758efd11ef6fe225b4617354286063ba3bc15633d3957644e2ccdb80b9e63f1b92412810b8290df58ef498d669fa70b907b698745d268d62658d71301e43a678f05a9ca1ec04d303380476d8f3865355e190580957248fc73cb8507a336b2f6b366719e6a9ceb97137d1af148f00538fe2d16cae4cd88a1de753fd3ddf125c5933301b9b56ab6d2476854ef2b

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(17351);
 script_version("1.9");
 script_set_attribute(attribute:"plugin_modification_date", value: "2014/10/06");

 script_name(english:"Kerberos configuration");
 script_summary(english:"Fills Kerberos information in the KB.");

 script_set_attribute(
  attribute:"synopsis",
  value:"This plugin is used to configure Kerberos server settings."
 );
 script_set_attribute(
  attribute:"description",
  value:
"This plugin lets a user enter information about the Kerberos server
that will be queried by some scripts (SMB and SSH) to log into
the remote hosts."
 );
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/17");

 script_set_attribute(attribute:"plugin_type", value:"settings");
 script_end_attributes();

 script_category(ACT_SETTINGS);

 script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
 script_family(english:"Settings");

 script_add_preference(name:"Kerberos Key Distribution Center (KDC) :", type:"entry", value:"");
 script_add_preference(name:"Kerberos KDC Port :", type:"entry", value:"88");
 script_add_preference(name:"Kerberos KDC Transport :", type:"radio", value:"tcp");
 script_add_preference(name:"Kerberos Realm (SSH only) :", type:"entry", value:"");
 exit(0);
}

kdc = script_get_preference("Kerberos Key Distribution Center (KDC) :");
if ( ! kdc ) exit(0);

kdc_port = int(script_get_preference("Kerberos KDC Port :"));
if ( kdc_port <= 0 ) exit(0);

replace_kb_item(name:"Secret/kdc_hostname", value:kdc);
replace_kb_item(name:"Secret/SSH/kdc_hostname", value:kdc);
replace_kb_item(name:"Secret/SMB/kdc_hostname", value:kdc);
replace_kb_item(name:"Secret/kdc_port", value:kdc_port);
replace_kb_item(name:"Secret/SSH/kdc_port", value:kdc_port);
replace_kb_item(name:"Secret/SMB/kdc_port", value:kdc_port);

kdc_transport =  script_get_preference("Kerberos KDC Transport :");
if ( !kdc_transport || ";" >< kdc_transport)
  kdc_transport = "tcp";

if ( kdc_transport == "tcp")
{
  replace_kb_item(name:"Secret/kdc_use_tcp", value:TRUE);
  replace_kb_item(name:"Kerberos/SMB/kdc_use_tcp", value:TRUE);
  replace_kb_item(name:"Kerberos/SSH/kdc_use_tcp", value:TRUE);
}

# this indicates all windows and ssh credentials should use the kerberos preferences read/saved by this plugin
replace_kb_item(name:"Kerberos/global", value:TRUE);

kdc_realm = script_get_preference("Kerberos Realm (SSH only) :");
if (kdc_realm) replace_kb_item(name:"Kerberos/SSH/realm", value:kdc_realm);
