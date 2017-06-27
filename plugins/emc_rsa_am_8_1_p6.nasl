#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84163);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/06/15 14:00:49 $");

  script_cve_id("CVE-2014-2516");
  script_bugtraq_id(71664);
  script_osvdb_id(115848);

  script_name(english:"EMC RSA Authentication Manager 8.x < 8.1 Patch 6 Unspecified URI Redirection");
  script_summary(english:"Checks the version of EMS RSA Authentication Manager.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a URI redirection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of EMC RSA Authentication Manager
8 prior to 8.1 Patch 6. It is, therefore, affected by an unspecified 
URI redirection vulnerability. An attacker can exploit this
vulnerability to redirect users to arbitrary websites.");
  # http://seclists.org/bugtraq/2014/Dec/att-80/ESA-2014-173.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?124dc052");
  script_set_attribute(attribute:"solution", value:"Upgrade to 8.1 Patch 6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rsa:authentication_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/EMC/AM/Version","Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/EMC/AM/Version");
verdisp = get_kb_item_or_exit("Host/EMC/AM/DisplayVersion");
fix     = "8.1.0.6.0";
fixdisp = "8.1 Patch 6";

if (version =~ "^8\." && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + verdisp +
      '\n  Fixed version     : ' + fixdisp +
      '\n';
    security_warning(extra:report, port:0);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "EMC RSA Authentication Manager", verdisp);
