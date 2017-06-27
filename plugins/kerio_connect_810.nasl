#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72393);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/10/07 18:00:11 $");

  script_cve_id("CVE-2011-3389");
  script_bugtraq_id(49778);
  script_osvdb_id(74829);
  script_xref(name:"CERT", value:"864643");

  script_name(english:"Kerio Connect < 8.1.0 SSL/TLS Information Disclosure (BEAST)");
  script_summary(english:"Checks for Kerio Connect version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of Kerio
Connect (formerly known Kerio MailServer) prior to 8.1.0. It is,
therefore, affected by an information disclosure vulnerability, known
as BEAST, in the SSL 3.0 and TLS 1.0 protocols due to a flaw in the
way the initialization vector (IV) is selected when operating in
cipher-block chaining (CBC) modes. A man-in-the-middle attacker can
exploit this to obtain plaintext HTTP header data, by using a
blockwise chosen-boundary attack (BCBA) on an HTTPS session, in
conjunction with JavaScript code that uses the HTML5 WebSocket API,
the Java URLConnection API, or the Silverlight WebClient API.

TLS 1.1, TLS 1.2, and all cipher suites that do not use CBC mode are
not affected.");
  script_set_attribute(attribute:"see_also", value:"http://www.kerio.com/connect/history/older");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2011/09/23/chromeandbeast.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/tls-cbc.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to Kerio Connect 8.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:kerio:connect");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("kerio_kms_641.nasl", "kerio_mailserver_admin_port.nasl");
  script_require_keys("kerio/port");
  script_require_ports("Services/kerio_mailserver_admin", 25, 465, 587);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_kb_item_or_exit('kerio/port');
ver = get_kb_item_or_exit('kerio/'+port+'/version');
display_ver = get_kb_item_or_exit('kerio/'+port+'/display_version');

# Versions prior to 7 are called MailServer; versions after are called Connect
if (ver =~ '^[0-6]\\.') product = "Kerio MailServer";
else product = "Kerio Connect";

# Workaround works for 8.0.1 and later
if (ver =~ '^8\\.0\\.[12]([^0-9]|$)' && report_paranoia < 2) audit(AUDIT_LISTEN_NOT_VULN, product, port, display_ver);

fixed_version = "8.1.0";

if (ver_compare(ver:ver, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity)
  {
    report =
      '\n  Product           : ' + product +
      '\n  Installed version : ' + display_ver +
      '\n  Fixed version     : ' + fixed_version +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}

audit(AUDIT_LISTEN_NOT_VULN, product, port, display_ver);
