#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100356);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/05/25 13:29:26 $");

  script_cve_id("CVE-2017-8291");
  script_osvdb_id(156431);
  script_xref(name:"EDB-ID", value:"41955");

  script_name(english:"Artifex Ghostscript .rsdparams Operator Handling Type Confusion RCE");
  script_summary(english:"Checks the Ghostscript version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a library that is affected by a
remote command execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Artifex Ghostscript installed on the remote Windows
host is 9.21 or earlier. It is, therefore, affected by a type
confusion error when handling the '.rsdparams' operator with a
'/OutputFile (%pipe%' substring. An unauthenticated, remote attacker
can exploit this, via a specially crafted EPS file, to bypass the
-dSAFER sandbox and execute arbitrary commands.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.ghostscript.com/show_bug.cgi?id=697799");
  script_set_attribute(attribute:"see_also", value:"https://bugs.ghostscript.com/show_bug.cgi?id=697808");
  # https://packetstormsecurity.com/files/142363/Ghostscript-9.21-Type-Confusion-Arbitrary-Command-Execution.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef741fb0");
  script_set_attribute(attribute:"solution", value:
"Refer to bug 697799 for possible workarounds or patches. A fixed
version of Ghostscript reportedly is scheduled for release in
September of 2017.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:artifex:ghostscript");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:artifex:gpl_ghostscript");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("ghostscript_detect.nbin");
  script_require_keys("installed_sw/Ghostscript");

  exit(0);
}

include("vcf.inc");

app = "Ghostscript";
constraints = [{ "max_version" : "9.21", "fixed_version" : "9.22", "fixed_display" : "Refer to bug 697799" }];

app_info = vcf::get_app_info(app:app, win_local:TRUE);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
