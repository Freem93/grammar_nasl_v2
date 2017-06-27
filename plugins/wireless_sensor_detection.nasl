#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(11559);
 # script_cve_id("CVE-MAP-NOMATCH");
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/29 20:13:38 $");

  script_name(english:"Network Chemistry Wireless Sensor Detection");
  script_summary(english:"Detects Wireless Sensor");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote host is vulnerable to information disclosure.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote host is a WSP100 802.11b Remote Sensor from Network Chemistry.

This device sniffs data flowing on the channels used by 802.11b and forwards it to
any host which 'subscribes' to this device.

An attacker may use this device to sniff 802.11b networks of the area it is
deployed from any location."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Filter incoming traffic to this host and make sure only
authorized hosts can connect to it."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");


 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/01");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
  family["english"] = "Service detection";
  script_family(english:family["english"]);
  script_dependencie("snmp_sysDesc.nasl");
  script_require_keys("SNMP/sysDesc");
  exit(0);
}

#
# The script code starts here
#
mydata = get_kb_item("SNMP/sysDesc");
if(!mydata) exit(0);
if("802.11b Remote Sensor" >< mydata)security_warning(0);
