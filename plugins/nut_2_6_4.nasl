#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59660);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/23 20:31:34 $");

  script_cve_id("CVE-2012-2944");
  script_bugtraq_id(53743);
  script_osvdb_id(82409);

  script_name(english:"Network UPS Tools < 2.6.4 addchar() Function Buffer Overflow");
  script_summary(english:"Checks the version of Network UPS Tools");

  script_set_attribute(attribute:"synopsis", value:
"The remote application is susceptible to a buffer overflow attack.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Network UPS Tools is affected by a buffer overflow caused by an error
in the 'addchar()' function. An unauthenticated, remote attacker
sending a specially crafted request to the server may trigger an
application crash or the execution of arbitrary code.");

  script_set_attribute(attribute:"solution", value:"Upgrade to Network UPS Tools 2.6.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"see_also", value:"http://trac.networkupstools.org/projects/nut/changeset/3633");
  script_set_attribute(attribute:"see_also", value:"http://alioth.debian.org/tracker/?func=detail&aid=313636");
  script_set_attribute(attribute:"see_also", value:"http://networkupstools.org/docs/user-manual.chunked/apis01.html");
  script_set_attribute(attribute:"see_also", value:"http://www.networkupstools.org/source/2.6/new-2.6.4.txt");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:networkupstools:nut");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("nut_detect.nasl");
  script_require_ports("Services/nut", 3493);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app = "Network UPS Tools";

# Prevent potential false positives.
#if (report_paranoia < 2)
#  audit(AUDIT_PARANOID);

# Get the ports that NUT have been found on.
port = get_service(svc:"nut", default:3493, exit_on_fail:TRUE);

# Get the instance's information from the KB.
key = "nut/" + port + "/";
banner = get_kb_item_or_exit(key + "banner");
ver = get_kb_item_or_exit(key + "version");

# Check whether the installation is vulnerable.
fix = "2.6.4";
if (ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_LISTEN_NOT_VULN, app, port, ver);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  Version source    : ' + banner +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
};

security_hole(port:port, extra:report);
