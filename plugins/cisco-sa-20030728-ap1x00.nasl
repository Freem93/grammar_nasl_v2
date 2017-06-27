#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17780);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/09/03 22:00:06 $");

  script_cve_id("CVE-2003-0511");
  script_bugtraq_id(8290);
  script_osvdb_id(2309);
  script_xref(name:"CISCO-BUG-ID", value:"CSCeb49842");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20030728-ap1x00");

  script_name(english:"HTTP GET Vulnerability in AP1x00");
  script_summary(english:"Checks IOS version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote device is running a version of IOS that has a flaw in
handling malformed URLs.  An attacker can take advantage of this
vulnerability by sending malformed URLs to the device possibly causing
it to reload, therefore creating a denial of service condition."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?25c13976");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory 
cisco-sa-20030728-ap1x00."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2003/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/version", "Host/Cisco/IOS/Platform");

  exit(0);
}

include("cisco_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
platform = get_kb_item_or_exit("Host/Cisco/IOS/Platform");

if ((platform =~ "^C11" || platform =~ "^C12" || platform =~ "^C14") &&
     check_release(version:version, patched:make_list("12.2(11)JA1"))) 
{
  security_warning(port:0, extra:'\nUpdate to ' + patch_update + ' or later.\n');
  exit(0);
}

exit(0, "The host is not affected.");
