#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77558);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/19 20:46:16 $");

  script_cve_id("CVE-2014-6064");
  script_bugtraq_id(69556);
  script_osvdb_id(109588);
  script_xref(name:"MCAFEE-SB", value:"SB10080");

  script_name(english:"McAfee Web Gateway Information Disclosure (SB10080)");
  script_summary(english:"Checks the version of McAfee Web Gateway.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of McAfee Web Gateway (MWG) that
is affected by an information disclosure vulnerability. There is an
unspecified flaw in the admin interface that is triggered when viewing
the top level 'Accounts' tab. This flaw allows a remote, authenticated
attacker to gain access to hashed password information.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10080");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch per the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:web_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_web_gateway_detect.nbin");
  script_require_keys("Host/McAfee Web Gateway/Version", "Host/McAfee Web Gateway/Display Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "McAfee Web Gateway";
version = get_kb_item_or_exit("Host/McAfee Web Gateway/Version");
version_display = get_kb_item_or_exit("Host/McAfee Web Gateway/Display Version");
fix = FALSE;

if (version =~ "^7\.[0-3]\.")
{
  fix_display = "7.3.2.9 Build 17463";
  fix = "7.3.2.9.0.17463";
}
else if (version =~ "^7\.4\.")
{
  fix_display = "7.4.2 Build 17499";
  fix = "7.4.2.0.0.17499";
}

if (fix && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version_display +
      '\n  Fixed version     : ' + fix_display +
      '\n';
      security_warning(extra:report, port:0);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version_display);
