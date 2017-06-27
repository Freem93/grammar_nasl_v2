#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(54923);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/22 14:17:41 $");

  script_cve_id("CVE-2011-1910");
  script_bugtraq_id(48007);
  script_osvdb_id(72540);
  script_xref(name:"CERT", value:"795694");
  script_xref(name:"Secunia", value:"44719");

  script_name(english:"ISC BIND 9 Large RRSIG RRsets Negative Caching Remote DoS");
  script_summary(english:"Checks version of BIND");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server may be affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote
installation of BIND is potentially affected by a denial of service
vulnerability.  If BIND queries a domain with large RRSIG resource
record sets it may trigger an assertion failure and cause the name
server process to crash due to an off-by-one error in a buffer size
check. 

Note that Nessus has only relied on the version itself and has not
attempted to determine whether or not the install is actually
vulnerable.");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f9dd6d57");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba92a18e");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d9a0b3f1");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c270545b");
  script_set_attribute(attribute:"see_also", value:"https://www.isc.org/software/bind/advisories/cve-2011-1910");

  script_set_attribute(attribute:"solution", value:
"Upgrade to BIND 9.4-ESV-R4-P1 / 9.6-ESV-R4-P1 / 9.7.3-P1 / 9.8.0-P2
or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/31");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version", "Settings/ParanoidReport");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2)
  exit(1, "This plugin only runs if 'Report paranoia' is set to 'Paranoid'.");

ver = get_kb_item_or_exit("bind/version");

# Check whether BIND is vulnerable, and recommend an upgrade.
fix = NULL;
if (ver =~ "9\.4-ESV-R(3|4$)")
  fix = "9.4-ESV-R4-P1";
else if (ver =~ "9\.6-ESV-R([2-3]|4$)")
  fix = "9.6-ESV-R4-P1";
else if (ver =~ "9\.6\.3")
  fix = "9.6-ESV-R4-P1";
else if (ver =~ "9\.7\.([1-2]|3$)")
  fix = "9.7.3-P1";
else if (ver =~ "^9\.8\.0($|-P1)")
  fix = "9.8.0-P2";

if (isnull(fix))
  exit(0, "BIND version " + ver + " is running on UDP port 53 and thus is not affected.");

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_hole(port:53, proto:"udp", extra:report);
} else security_hole(port:53, proto:"udp");
