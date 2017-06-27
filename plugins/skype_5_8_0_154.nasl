#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(57877);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/02/10 12:20:29 $");

  script_bugtraq_id(51853);
  script_osvdb_id(78818);
  script_xref(name:"Secunia", value:"47856");

  script_name(english:"Skype for Windows < 5.8.0.154 Unspecified Vulnerability (uncredentialed check)");
  script_summary(english:"Checks Skype timestamp");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Skype install has an unspecified vulnerability."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"According to its timestamp, the version of Skype installed on the
remote Windows host reportedly has an as-yet unspecified
vulnerability."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://blogs.skype.com/garage/2012/02/skype_for_windows_update.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Skype for Windows 5.8.0.154 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:skype:skype");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("skype_version.nbin", "os_fingerprint.nasl");
  script_require_keys("Services/skype");
  script_require_ports("Services/www");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


port = get_service(svc:"skype", exit_on_fail:TRUE);


# The flaw only affects Windows hosts.
skype_version = get_kb_item("Skype/"+port+"/skypeVersion");
if (!isnull(skype_version))
{
  if ("Windows" >!< skype_version) 
    exit(0, "The "+skype_version+" install listening on port "+port+" is not affected since it's not Skype for Windows.");
}
else
{
  if (report_paranoia < 2)
  {
    os = get_kb_item_or_exit("Host/OS");
    if ("Windows" >!< os) exit(0, "The host does not appear to be running Windows.");
  }
}


# nb: "ts = 1201271324" => "version = 5.8.0.154"
ts = get_kb_item_or_exit("Skype/"+port+"/stackTimeStamp");
if (ts < 1201271324)
{
  if (report_verbosity > 0 && !isnull(skype_version))
  {
    report = 
      '\n  Installed version : ' + skype_version + 
      '\n  Fixed version     : Skype for Windows Version 5.8.0.154' +
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
