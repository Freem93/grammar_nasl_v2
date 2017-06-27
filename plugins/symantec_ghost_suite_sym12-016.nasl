#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62716);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/06 17:22:01 $");

  script_cve_id("CVE-2012-0306");
  script_bugtraq_id(55748);
  script_osvdb_id(86151);

  script_name(english:"Symantec Ghost Solution Suite Backup File Handling Memory Corruption (SYM12-016)");
  script_summary(english:"Checks Symantec Ghost Solution Suite build number");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by a memory corruption vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Symantec Ghost Solution Suite install on the remote Windows host is
earlier than build 11.5.1.2620.  As such, it is potentially affected by
a memory corruption vulnerability when parsing specially crafted '.gho'
files.  By exploiting this flaw, a remote attacker could execute
arbitrary code on the remote host subject to the privileges of the user
running the affected application.");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2012&suid=20121010_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f65f819");
  # http://www.symantec.com/business/support/index?page=content&id=TECH197839
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?46e76df5");
  script_set_attribute(attribute:"solution", value:

"If necessary, upgrade to Symantec Ghost Solution Suite version 2.5.1
and ensure that the install is build 11.5.1.2266 or above.  Then apply
patch GSS25x_b2620, which results in build 11.5.1.2620.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:ghost_solutions_suite");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("symantec_ghost_suite_installed.nasl");
  script_require_keys("SMB/Symantec Ghost Suite/Build", "SMB/Symantec Ghost Suite/Path");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

build = get_kb_item_or_exit("SMB/Symantec Ghost Solution Suite/Build");
path = get_kb_item_or_exit("SMB/Symantec Ghost Solution Suite/Path");

fixed_build = '11.5.1.2620';
if (build =~ '^11\\.' && ver_compare(ver:build, fix:fixed_build) == -1)
{
  port = get_kb_item('SMB/transport');
  if (report_verbosity > 0)
  {
    report =
      '\n  Path            : ' + path +
      '\n  Installed build : ' + build +
      '\n  Fixed build     : ' + fixed_build + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, 'Symantec Ghost Solution Suite', path);
