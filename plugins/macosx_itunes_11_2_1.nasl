#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74093);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/05/10 13:37:30 $");

  script_cve_id("CVE-2014-1347");
  script_bugtraq_id(67457);
  script_osvdb_id(107081);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2014-05-16-1");

  script_name(english:"iTunes < 11.2.1 User Directory Insecure Permissions Vulnerability (Mac OS X)");
  script_summary(english:"Checks iTunes version");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by an
insecure permissions vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of iTunes installed on the remote Mac OS X host is older
than 11.2.1. It is, therefore, affected by an insecure permissions
vulnerability.

An insecure permissions vulnerability exists where the '/Users' and
'/Users/Shared' directories have world-writable permissions. This
could allow a local attacker to manipulate the contents or gain
escalated privileges.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT6251");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/532141/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to iTunes 11.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_itunes_detect.nasl");
  script_require_keys("Host/MacOSX/Version", "installed_sw/iTunes");

  exit(0);
}

include("vcf.inc");

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

app_info = vcf::get_app_info(app:"iTunes");

constraints = [{"fixed_version" : "11.2.1"}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
