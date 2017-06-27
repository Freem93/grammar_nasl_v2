#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85226);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id("CVE-2015-5358");
  script_bugtraq_id(75731);
  script_osvdb_id(124295);

  script_name(english:"Juniper Junos LAST_ACK State DoS (JSA10686)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability due
to the improper handling of TCP connection transitions to the
LAST_ACK state when the device has more data to send. A remote
attacker can exploit this cause the socket to be stuck in the LAST_ACK
state indefinitely, leading to exhaustion of memory buffers (mbufs)
and connections.

Note that Nessus has not tested for this issue or the host
configuration but has instead relied only on the application's
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10686");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10686.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("junos.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_array();

fixes['12.1X44'] = '12.1X44-D50';
fixes['12.1X46'] = '12.1X46-D35';
fixes['12.1X47'] = '12.1X47-D25';
fixes['12.3']    = '12.3R9';
fixes['12.3X48'] = '12.3X48-D15';
fixes['13.2']    = '13.2R7';
fixes['13.2X51'] = '13.2X51-D35';
fixes['13.2X52'] = '13.2X52-D25';
fixes['13.3']    = '13.3R6';
fixes['14.1']    = '14.1R3-S2';
fixes['14.1X53'] = '14.1X53-D12';
fixes['14.1X55'] = '14.1X55-D25';
fixes['14.2']    = '14.2R2';
fixes['15.1']    = '15.1R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (report_verbosity > 0)
{
  report = get_report(ver:ver, fix:fix);
  security_hole(port:0, extra:report);
}
else security_hole(0);
