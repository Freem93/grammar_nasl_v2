#
# (C) Tenable Network Security, Inc.
#

# This is the "check" for an old flaw (published in March 2002). We can't
# actually determine the version of the remote mod_frontpage, so we issue
# an alert each time we detect it as running.
#
# Mandrake's Security Advisory states that the flaw is remotely exploitable,
# while FreeBSD's Security advisory (FreeBSD-SA-02:17) claims this is only
# locally exploitable.
#
# In either case, we can't remotely determine the version of the server, so
#
# Ref:
# From: FreeBSD Security Advisories <security-advisories@freebsd.org>
# To: FreeBSD Security Advisories <security-advisories@freebsd.org>
# Subject: FreeBSD Ports Security Advisory FreeBSD-SA-02:17.mod_frontpage
# Message-Id: <200203121428.g2CES9U64467@freefall.freebsd.org>

include("compat.inc");

if (description)
{
 script_id(11303);
 script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2014/05/26 01:15:51 $");

 script_cve_id("CVE-2002-0427");
 script_bugtraq_id(4251);
 script_osvdb_id(14410);

 script_name(english:"mod_frontpage for Apache fpexec Remote Overflow");
 script_summary(english:"Checks for the presence of mod_frontpage");

 script_set_attribute(attribute:"synopsis", value:"The remote web server module has a buffer overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host is using the Apache mod_frontpage module.

mod_frontpage older than 1.6.1 is vulnerable to a buffer overflow that
could allow an attacker to gain root access.

*** Since Nessus was not able to remotely determine the version *** of
mod_frontage you are running, you are advised to manually *** check
which version you are running as this might be a false *** positive.

If you want the remote server to be remotely secure, we advise you do
not use this module at all.");
 script_set_attribute(attribute:"solution", value:"Disable this module.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/03/07");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/02");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:christof_pohl:improved_mod_frontpage");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl");
 script_require_keys("www/apache", "Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if(!banner)exit(0);

if (egrep(pattern:"^Server:.*Apache.*FrontPage.*", string:banner))
{
  security_hole(port);
}
