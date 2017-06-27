#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(53845);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/13 15:33:30 $");

  script_cve_id("CVE-2011-2074");
  script_bugtraq_id(47747);
  script_osvdb_id(72232);

  script_name(english:"Skype for Mac 5.x < 5.1.0.922 Unspecified Remote Code Execution (uncredentialed check)");
  script_summary(english:"Checks Skype timestamp");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Skype client allows arbitrary code execution."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"According to its timestamp, the version of Skype installed on the
remote Mac OS X host reportedly allows an attacker to send a specially
crafted message to a user on the affected host and execute arbitrary
code. 

Note that by default, such a message would have to come from someone
in a user's Skype Contact List."
  );
  # http://www.purehacking.com/blogs/gordon-maddern/skype-0day-vulnerabilitiy-discovered-by-pure-hacking
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6a8cef8d"
  );
  # http://blogs.skype.com/security/2011/05/security_vulnerability_in_mac.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c36790c1"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Skype for Mac 5.1.0.922 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:skype:skype");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("skype_version.nbin", "os_fingerprint.nasl");
  script_require_keys("Services/skype");
  script_require_ports("Services/www");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


port = get_service(svc:"skype", exit_on_fail:TRUE);


# The flaw only affects Mac OS X hosts.
skype_version = get_kb_item("Skype/"+port+"/skypeVersion");
if (!isnull(skype_version))
{
  if ("Mac OS X" >!< skype_version) 
    exit(0, "The "+skype_version+" install listening on port "+port+" is not affected since it's not Skype for Mac.");
}
else
{
  if (report_paranoia < 2)
  {
    os = get_kb_item_or_exit("Host/OS");
    if ("Mac OS X" >!< os) exit(0, "The host does not appear to be running Mac OS X.");
  }
}


# nb: "ts = 1103301002" => "version = 5.1.0.922"
#     "ts = 1101202353" => "version = 5.0.0.7980".
ts = get_kb_item_or_exit("Skype/"+port+"/stackTimeStamp");
if (ts >= 1101202353 && ts < 1103301002)
{
  if (report_verbosity > 0 && !isnull(skype_version))
  {
    report = 
      '\n  Installed version : ' + skype_version + 
      '\n  Fixed version     : Skype for Mac OS X Version 5.1.0.922\n';
    security_warning(port:port, extra:report);
  }
  security_warning(port);
  exit(0);
}
else
{
  if (isnull(skype_version)) exit(0, "The Skype install listening on port "+port+" is not affected based on its timestamp ("+ts+").");
  else exit(0, "The Skype install listening on port "+port+" is not affected based on its version ("+skype_version+").");
}
