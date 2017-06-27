#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82529);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/19 20:46:16 $");

  script_cve_id("CVE-2015-1619");
  script_bugtraq_id(73420);
  script_osvdb_id(117410);
  script_xref(name:"MCAFEE-SB", value:"SB10099");

  script_name(english:"McAfee Email Gateway Digest Token Reflected XSS (SB10099)");
  script_summary(english:"Checks the MEG version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a reflected cross-site scripting
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of McAfee Email Gateway (MEG) installed
that is affected by a reflected cross-site scripting vulnerability due
to improper validation of user-supplied input to unspecified tokens in
digest messages. A remote attacker can exploit this, via a specially
crafted request, to execute arbitrary web script or HTML in a user's
browser session.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10099");
  script_set_attribute(attribute:"solution", value:"Apply the relevant hotfix referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:email_gateway");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_dependencies("mcafee_email_gateway_version.nbin");
  script_require_keys("Host/McAfeeSMG/name", "Host/McAfeeSMG/version", "Host/McAfeeSMG/patches");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = get_kb_item_or_exit("Host/McAfeeSMG/name");
version = get_kb_item_or_exit("Host/McAfeeSMG/version");
patches = get_kb_item_or_exit("Host/McAfeeSMG/patches");

# Determine fix. 5.6\7.0 appear to be
# at end of life (4/1/2015). McAfee
# may still be releasing patches on a
# per customer basis, however they do
# not appear to be available via the
# autoupdate feature of McAfee Email
# Gateway.
if (version =~ "^5\.6\.")
{
  fix = "5.6.9999.999";
  hotfix = "5.6h1021351";
  if (report_paranoia < 2) audit(AUDIT_PARANOID);
}
else if (version =~ "^7\.0\.")
{
  fix = "7.0.9999.999";
  hotfix = "7.0.5h1021346";
  if (report_paranoia < 2) audit(AUDIT_PARANOID);
}
else if (version =~ "^7\.5\.")
{
  fix = "7.5.3205.100";
  hotfix = "7.5.6-3205.100";
}
else if (version =~ "^7\.6\.")
{
  fix    = "7.6.3206.103";
  hotfix = "7.6.3.2-3206.103";
}
else audit(AUDIT_INST_VER_NOT_VULN, version);

if (ver_compare(ver:version,fix:fix,strict:FALSE) == -1 && hotfix >!< patches)
{
  port = 0;
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  if (report_verbosity > 0)
  {
    if(hotfix)
      report = '\n' + app_name + ' ' + version + ' is missing patch ' + hotfix + '.\n';
    security_note(extra:report, port:port);
  }
  else security_note(port:port);
  exit(0);
}
else audit(AUDIT_PATCH_INSTALLED, hotfix, app_name, version);
