#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42824);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2009-3853", "CVE-2009-3854", "CVE-2009-3855");
  script_bugtraq_id(36916);
  script_osvdb_id(59632, 59633, 59634);
  script_xref(name:"Secunia", value:"32534");

  script_name(english:"IBM Tivoli Storage Manager Client Multiple Vulnerabilities (swg21405562)");
  script_summary(english:"Does a version check on the TSM client's web server");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote backup client is susceptible to multiple attacks."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running an IBM Tivoli Storage Manager (TSM) client.
The version running on the remote host has one or more of the
following vulnerabilities :

  - A remote stack-based buffer overflow in the client
    acceptor daemon (CAD) scheduler could lead to the
    execution of arbitrary code. (CVE-2009-3853)

  - A remote, stack-based buffer overflow in the traditional
    scheduler could lead to the execution of arbitrary
    code. (CVE-2009-3854)

  - There is an unspecified, unauthorized access
    vulnerability in the Unix, Linux, and OS/400 API clients
    when specifying the MAILPROG option.  This vulnerability
    reportedly allows a remote attacker to modify arbitrary
    files on the remote host. (CVE-2009-2855)"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to the relevant version of Tivoli Storage Manager client
referenced in the vendor's advisory."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'IBM Tivoli Storage Manager Express CAD Service Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(119);
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/11/03"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/11/03"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/11/16"
  );
 script_cvs_date("$Date: 2016/11/23 20:31:32 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:ibm:tivoli_storage_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "ibm_tsm_cad_detect.nasl");
  script_require_ports("Services/www", 1581);
  script_require_keys("Services/ibm_tsm_cad");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:1581, embedded:TRUE);
tsm_port = get_kb_item("Services/ibm_tsm_cad");
if (isnull(tsm_port)) exit(1, "The 'Services/ibm_tsm_cad' KB item is missing.");

# Make sure the banner looks like TSM unless we're paranoid
if (report_verbosity < 2)
{
  banner = get_http_banner(port:port);

  if (isnull(banner))
    exit(1, "Unable to get web server banner on port "+port+".");
  if ('Server: TSM_HTTP' >!< banner)
    exit(1, "The web server on port "+port+" isn't TSM_HTTP.");
}


# Grab the main page.
res = http_send_recv3(method:"GET", item:"/BACLIENT", port:port);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");


# If it looks like TSM Client...
if ('adsm.cadmin.clientgui.DDsmApplet.class"' >< res[1])
{
  # Pull out the version number.
  ver = NULL;

  pat = ' version *= *"([0-9][0-9.]+) *"';
  matches = egrep(pattern:pat, string:res[1]);
  if (matches)
  {
    foreach match (split(matches, keep:FALSE))
    {
      item = eregmatch(pattern:pat, string:match);
      if (!isnull(item))
      {
        ver = item[1];
        if (ver[strlen(ver)-1] == '.') ver = substr(ver, 0, strlen(ver)-2);
        break;
      }
    }
  }
  if (!isnull(ver))
  {
    iver = split(ver, sep:'.', keep:FALSE);
    for (i=0; i < max_index(ver); i++)
      iver[i] = int(iver[i]);

    # TSM 6.1.x < 6.1.0.2
    if ((iver[0] == 6 && iver[1] == 1 && iver[2] == 0 && iver[3] < 2))
      fixed_ver = '6.1.0.2';

    # Checks all 5.x branches
    if (iver[0] == 5)
    {
      # TSM 5.5.x < 5.5.2.2
      if (iver[1] == 5 && (iver[2] < 2 || (iver[2] == 2 && iver[3] < 2)))
        fixed_ver = '5.5.2.2';

      # TSM 5.4.x < 5.4.3
      if (iver[1] == 4 && iver[2] < 3)
        fixed_ver = '5.4.3';

      # TSM / TSM Express 5.3 < 5.3.6.7
      if (iver[1] == 3 && (iver[2] < 6 || (iver[2] == 6 && iver[3] < 7)))
        fixed_ver = '5.3.6.7';
    }

    if (!isnull(fixed_ver))
    {
      if (report_verbosity > 0)
      {
        report = "
Installed version : " + ver + "
Fixed version     : " + fixed_ver + "
";
        security_hole(port:tsm_port, extra:report);
      }
      else security_hole(tsm_port);
    }
    else exit(0, "The host is not affected on port "+tsm_port+".");
  }
  else exit(1, "Unable to extract version of TSM client from port "+port+".");
}
else exit(1, "The web server on port "+port+" doesn't look like TSM.");

