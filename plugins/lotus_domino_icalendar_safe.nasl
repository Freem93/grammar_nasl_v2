#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53534);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_cve_id("CVE-2010-3407");
  script_bugtraq_id(43219);
  script_osvdb_id(68040);

  script_name(english:"IBM Lotus Domino iCalendar Email Address ORGANIZER:mailto Header Remote Overflow");
  script_summary(english:"Checks version in Lotus Domino's SMTP banners");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote mail service is affected by a remote stack-based buffer
overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version, the remote SMTP service is an
instance of IBM Lotus Domino that is is affected by a remote
stack-based buffer overflow vulnerability because it fails to perform
adequate boundary checks on user-supplied input.

Successfully exploiting this issue may allow remote attackers to
execute arbitrary code in the context of the 'nrouter.exe' Lotus
Domino server process.  Failed attacks will cause denial of service
conditions."
  );
   # http://www-10.lotus.com/ldd/fixlist.nsf/8d1c0550e6242b69852570c900549a74/613a204806e3f211852576e2006afa3d?OpenDocument
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?306e4571"
  );
   # http://www-10.lotus.com/ldd/fixlist.nsf/8d1c0550e6242b69852570c900549a74/af36678d60bd74288525778400534d7c?OpenDocument
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f176cb3"
  );
   # http://www-01.ibm.com/software/lotus/products/domino/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6fa36abe"
  );
   # http://www-10.lotus.com/ldd/fixlist.nsf/8d1c0550e6242b69852570c900549a74/52f9218288b51dcb852576c600741f72?OpenDocument
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b67c63ae"
  );
   # http://www-01.ibm.com/support/docview.wss?uid=swg21446515
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b1c391a1"
  );
   # http://labs.mwrinfosecurity.com/assets/159/mwri_lotus-domino-ical-stack-overflow_2010-09-14.pdf
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cd9e7c99"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to IBM Lotus Domino 8.0.2 FP5 / 8.5.1 FP2 / 8.5.2 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'IBM Lotus Domino iCalendar MAILTO Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:ibm:lotus_domino");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);

  exit(0);
}

include("global_settings.inc");
include("smtp_func.inc");
include("misc_func.inc");

version = NULL;
vulnerable = FALSE;

port = get_service(svc:'smtp', default:25, exit_on_fail:TRUE);

banner = get_smtp_banner(port:port);
if (!banner) exit(1, "The SMTP server listening on port "+port+" did not return a banner.");
if (" ESMTP Service " >< banner && "(Lotus Domino" >< banner)
{
  items = eregmatch(pattern:"ESMTP Service \(Lotus Domino Release (.*)\)", string:banner);
  if (items)
  {
    version = items[1];
  }
}
else exit(0, "The SMTP server listening on port "+port+" is not Lotus Domino.");

if (version)
{
  major = 0;
  minor = 0;

  if ("FP" >< version)
  {
    sp_ver = split(version, sep:"FP", keep:FALSE);
    ver = sp_ver[0];
    fp = int(sp_ver[1]);
  }
  else
  {
    ver = version;
    fp = 0;
  }

  ver_maj_min = split(ver, sep:".", keep:FALSE);
  major = int(ver_maj_min[0]);
  minor = int(ver_maj_min[1]);
  if ( major == 0 ) exit(1, "Could not parse the banner "+banner+" on port "+port);

  if(!isnull(ver_maj_min[2]))
  {
    build = int(ver_maj_min[2]);
  }
  else
  {
    build = 0;
  }

  #Versions Not Vuln, Everything else is vuln and wont be patched.
  #8.0.2 FP5, 8.5.2, 8.5.1 FP2
  if (
    (major > 8) ||
    (major == 8 && minor == 0 && build == 2 && fp >= 5) ||
    (major == 8 && minor == 5 && build >= 2 && fp >= 0) ||
    (major == 8 && minor == 5 && build == 1 && fp >= 2) ||
    (major == 8 && minor >= 6)
    )
    {
      vulnerable = FALSE;
    }
  else 
      vulnerable = TRUE;
}

if (vulnerable == TRUE)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Banner            : ' + banner +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 8.0.2 FP5 / 8.5.1 FP2 / 8.5.2\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);

}
else exit(0, "Lotus Domino "+version+" is listening on port "+port+" and not affected.");

