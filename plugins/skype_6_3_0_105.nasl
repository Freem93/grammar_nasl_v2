#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(66694);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/05/31 00:43:00 $");

  script_bugtraq_id(58519, 58805);
  script_osvdb_id(91459, 91974);

  script_name(english:"Skype for Windows < 6.3.0.105 Multiple Vulnerabilities (uncredentialed check)");
  script_summary(english:"Checks Skype timestamp");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Skype install is potentially affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its timestamp, the version of Skype installed on the
remote Windows host is potentially affected by the following
vulnerabilities :

  - An error exists related to the Click to Call Service
    (c2c_service.exe) that could allow a local attacker to
    cause arbitrary DLL files to be loaded, thus allowing
    code execution.

  - Several other unspecified errors exist."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2013/Mar/94");
  script_set_attribute(attribute:"see_also", value:"http://blogs.skype.com/2013/03/14/skype-6-3-for-windows/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Skype for Windows 6.3.0.105 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:skype:skype");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("skype_version.nbin", "os_fingerprint.nasl");
  script_require_keys("Services/skype");
  script_require_ports("Services/www");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


port = get_service(svc:"skype", exit_on_fail:TRUE);


# The flaw only affects Windows hosts.
skype_version = get_kb_item("Skype/"+port+"/skypeVersion");
if (!isnull(skype_version))
{
  if ("Windows" >!< skype_version)
    audit(AUDIT_NOT_LISTEN, "Skype for Windows", port);
}
else
{
  if (report_paranoia < 2)
  {
    os = get_kb_item_or_exit("Host/OS");
    audit(AUDIT_OS_NOT, "Windows");
  }
}


# nb: "ts = 1302281334" => "version = 6.3.0.105"
ts = get_kb_item_or_exit("Skype/"+port+"/stackTimeStamp");
if (ts < 1302281334)
{
  if (report_verbosity > 0 && !isnull(skype_version))
  {
    report =
      '\n  Installed version : ' + skype_version +
      '\n  Fixed version     : Skype for Windows Version 6.3.0.105' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else
{
  if (isnull(skype_version)) exit(0, "The Skype install listening on port "+port+" is not affected based on its timestamp ("+ts+").");
  else exit(0, "The Skype install listening on port "+port+" is not affected based on its version ("+skype_version+").");
}
