#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62390);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/10/03 11:22:56 $");

  script_cve_id("CVE-2012-4895", "CVE-2012-4896");
  script_bugtraq_id(55596);
  script_osvdb_id(85568, 85569);
  script_xref(name:"MSVR", value:"MSVR12-014");

  script_name(english:"SumatraPDF < 2.1 Multiple Vulnerabilities");
  script_summary(english:"Checks version of SumatraPDF");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a PDF reader installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of SumatraPDF installed on the remote Windows host is
earlier than 2.1.  As such, it is potentially affected by multiple
memory corruption vulnerabilities.  By tricking a user into opening a
specially crafted PDF file, a remote, unauthenticated attacker could
execute arbitrary code on the remote host, subject to the privileges of
the user running the affected application.");
  script_set_attribute(attribute:"see_also", value:"http://blog.kowalczyk.info/software/sumatrapdf/news.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to SumatraPDF 2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:krystztof_kowalczyk:sumatrapdf");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("sumatra_pdf_installed.nasl");
  script_require_keys("SMB/SumatraPDF/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/SumatraPDF/Version");
path = get_kb_item_or_exit("SMB/SumatraPDF/Path");

fixed_version = '2.1.0.0';
if (ver_compare(ver:version, fix:fixed_version) == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_hole(get_kb_item('SMB/transport'));
}
else audit(AUDIT_INST_PATH_NOT_VULN, 'SumatraPDF', version, path);
