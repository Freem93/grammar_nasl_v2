#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86605);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id("CVE-2014-6448");
  script_osvdb_id(128907);
  script_xref(name:"JSA", value:"JSA10695");

  script_name(english:"Juniper Junos Multiple Python Privilege Escalation (JSA10695)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is potentially affected by multiple unspecified flaws
related to Python. A local attacker can exploit these to run arbitrary
Python code and thus gain elevated privileges.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10695");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10695.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", 'Host/Juniper/model');

  exit(0);
}

include("audit.inc");
include("junos.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

report = FALSE;
fix = NULL;
if((model =~ "^EX" || model =~ "^QFX") && ver =~ "^13.2X5[1-2]($|[^0-9])") {
  report = 
   '\n  Version : '+ver+
   '\n  Model   : '+model+
   '\n  Note    : The device may be affected but no fix has been'+
   '\n            issued by Juniper. Applying the workaround is'+
   '\n            suggested.'+
   '\n';
}
else
{
  fixes = make_array();
  fixes['13.2'   ] = '13.2R5';
  fixes['13.3'   ] = '13.3R3';

  fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
}

if (report_verbosity > 0)
{
  if(!report)
    report = get_report(ver:ver, fix:fix);
  security_hole(port:0, extra:report);
}
else security_hole(0);
