#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76402);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/20 14:03:01 $");

  script_cve_id("CVE-2014-0160");
  script_bugtraq_id(66690);
  script_osvdb_id(105465);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");

  script_name(english:"Kerio Connect 8.2.x < 8.2.4 Heartbeat Information Disclosure (Heartbleed)");
  script_summary(english:"Checks the Kerio Connect version.");

  script_set_attribute(attribute:"synopsis", value:"The remote mail server is affected by the Heartbleed vulnerability");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of Kerio
Connect (formerly Kerio MailServer) version 8.2.x prior to 8.2.4. It
is, therefore, affected by an out-of-bounds read error, known as the
'Heartbleed Bug' in the included OpenSSL version.

This error is related to handling TLS heartbeat extensions that could
allow an attacker to obtain sensitive information such as primary key
material, secondary key material, and other protected content. Note
this affects both client and server modes of operation.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # http://kb.kerio.com/product/kerio-operator/openssl-vulnerability-cve-2014-0160-heartbleed-1585.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0e9520d1");
  # http://www.kerio.com/support/kerio-connect/release-history-older
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ac0f693");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"https://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to Kerio Connect 8.2.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:kerio:connect");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

fixed_version = "8.2.4";
if (
  ver =~ "^8\.2\." &&
  ver_compare(ver:ver, fix:fixed_version, strict:FALSE) == -1
)
{
  if (report_verbosity)
  {
    report =
      '\n  Product           : ' + product +
      '\n  Installed version : ' + display_ver +
      '\n  Fixed version     : ' + fixed_version +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}

audit(AUDIT_LISTEN_NOT_VULN, product, port, display_ver);
