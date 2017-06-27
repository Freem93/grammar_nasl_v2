#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(43877);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/03 14:16:36 $");

  script_bugtraq_id(37726);
  script_osvdb_id(61671);
  script_xref(name:"EDB-ID", value:"11131");
  script_xref(name:"Secunia", value:"38145");

  script_name(english:"TurboFTP Server < 1.00.720 DoS");
  script_summary(english:"Checks version in FTP banner");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a denial of service
vulnerability."
  );
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of
TurboFTP Server earlier than 1.00.720.  Such versions are reportedly
affected by a denial of service vulnerability.  

By sending an overly long parameter to 'DELE' FTP command, it may be
possible for an authenticated FTP user to crash the affected service."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b52591ba");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2010/Jan/201");
  script_set_attribute(attribute:"see_also", value:"http://www.tbsoftinc.com/tbserver/turboftp-server-releasenotes.htm" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to TurboFTP Server V1.00.720 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_require_keys("ftp/turboftp");
  exit(0);
}

include("global_settings.inc");
include("ftp_func.inc");

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port:port);
if (!banner) exit(1, "No FTP banner found on port "+port+".");

if ("TurboFTP Server" >!< banner) exit(0, "Banner on port "+port+" doesn't look like TurboFTP Server.");

banner  = egrep(pattern:" TurboFTP Server [0-9.]+",string:banner);
version = strstr(banner, " TurboFTP Server ") - " TurboFTP Server ";
version = version - strstr(version, " ready.");

if(version && ereg(pattern:"^[0-9.]+$",string:version))
{
  ver = split(version, sep:".", keep:FALSE);

  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  if((ver[0]  < 1 ) ||
     (ver[0] == 1 && ver[1] == 0 && ver[2] < 720))
  { 
    if (report_verbosity > 0)
    {
      report = '\n' +
        'TurboFTP Server version '+ version+ ' appears to be running on the remote host'+ '\n' +
        'based on the following banner :' + '\n' +
        '\n' +
        '  ' + banner + '\n' +
        '\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port:port);

    exit(0);
  }
  else
   exit(0, "TurboFTP Server version "+ version + " is installed on port "+ port + " and is not vulnerable.");
}
else
  exit(1, "It was not possible to extract the TurboFTP Server version listening on port "+ port + " from the banner " + banner + ".");
