#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62734);
  script_version('$Revision: 1.4 $');
  script_cvs_date("$Date: 2014/05/24 02:02:50 $");

  script_cve_id("CVE-2012-5671");
  script_bugtraq_id(56285);
  script_osvdb_id(86616);

  script_name(english:"Exim 4.70 - 4.80 DKIM DNS Record Parsing Remote Buffer Overflow");
  script_summary(english:"Checks version of SMTP banner");

  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is potentially affected by a buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Exim running on the remote host
is between 4.70 and 4.80 inclusive.  It therefore is potentially
affected by a remote, heap-based buffer overflow vulnerability when
decoding DKIM (DomainKeys Identified Mail) DNS records that can be
triggered by a specially crafted email sent from a domain under the
attacker's control. 

By exploiting this flaw, a remote, unauthenticated attacker could
execute arbitrary code on the remote host subject to the privileges of
the user running the affected application.

Note that this issue is only exploitable when exim is built with DKIM
support, which is true by default, and has not been disabled.  Note too
that Nessus has not checked whether either condition is true.");
  script_set_attribute(attribute:"see_also", value:"ftp://ftp.exim.org/pub/exim/ChangeLogs/ChangeLog-4.80.1");
  script_set_attribute(attribute:"see_also", value:"https://lists.exim.org/lurker/message/20121026.080330.74b9147b.en.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Exim 4.80.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/29");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:exim:exim");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  script_require_keys("Settings/ParanoidReport");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_service(svc:"smtp", default:25, exit_on_fail:TRUE);

banner = get_smtp_banner(port:port);
if (!banner) exit(1, "Failed to retrieve the banner from the SMTP server listening on port "+port+".");
if ("Exim" >!< banner) exit(0, "The banner from the SMTP server listening on port "+port+" is not from Exim.");

matches = eregmatch(pattern:"220.*Exim ([0-9\.]+)", string:banner);
if (isnull(matches)) exit(1, "Failed to determine the version of Exim based on the banner from the SMTP server listening on port "+port+".");

version = matches[1];
if (ereg(pattern:'^(4\\.(7[0-9]([^0-9]|$)|80$))', string:version))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Banner            : ' + banner +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 4.80.1';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'Exim', port, version);
