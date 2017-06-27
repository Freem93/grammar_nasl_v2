#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72245);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/16 19:35:38 $");

  script_cve_id("CVE-2014-0675");
  script_bugtraq_id(65101);
  script_osvdb_id(102377);
  script_xref(name:"CISCO-BUG-ID", value:"CSCue07471");

  script_name(english:"Cisco TelePresence Video Communication Server Expressway Default SSL Certificate");
  script_summary(english:"Checks SHA1 fingerprint");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is using a well-known SSL certificate whose private
key has been published.");
  script_set_attribute(attribute:"description", value:
"The X.509 certificate of the remote host is known to ship by default
with the remote service / device.  The private key for this cert has
been published, therefore the SSL communications done with the remote
host cannot be considered secret as anyone with the ability to snoop the
traffic between the remote host and the clients could decipher the
traffic or launch a man-in-the-middle attack.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2014-0675
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bccf389b");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=32540");
  script_set_attribute(attribute:"solution", value:
"Purchase or generate a proper certificate for this service and replace
it, or ask your vendor for a way to do so.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_video_communication_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("ssl_supported_versions.nasl", "cisco_telepresence_video_communication_server_detect.nbin");
  script_require_keys("Cisco/TelePresence_VCS/Version", "SSL/Supported");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("x509_func.inc");

get_kb_item_or_exit("Cisco/TelePresence_VCS/Version");
get_kb_item_or_exit("SSL/Supported");

ports = get_ssl_ports();
if (isnull(ports) || max_index(ports) == 0)
  audit(AUDIT_NOT_DETECT, "An SSL HTTP server");

fingerprint = "24:80:1D:28:F9:D7:A8:0E:25:0C:79:93:EC:D7:77:13:C0:A7:2E:A2";
vuln = FALSE;

foreach port ( ports )
{
  cert = get_server_cert(port:port, encoding:"der");
  if (isnull(cert))
    continue;

  sha1 = toupper(hexstr(SHA1(cert)));
  digest = "";
  for (i = 0 ; i < strlen(sha1); i += 2)
    digest = strcat(digest, sha1[i], sha1[i+1], ":");

  digest = substr(digest, 0, strlen(digest) - 2 );

  if (fingerprint == digest)
  {
    vuln = TRUE;
    break;
  }
}

if (vuln)
{
  if (report_verbosity > 0)
  {
    report = '\n  SSL port         : ' + port +
             '\n  SHA1 fingerprint : ' + digest +
             '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port:port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "SSL HTTP server", port);
