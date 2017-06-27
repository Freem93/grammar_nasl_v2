#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78427);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/20 13:54:17 $");

  script_cve_id("CVE-2014-2927");
  script_bugtraq_id(69461);
  script_osvdb_id(110595);
  script_xref(name:"EDB-ID", value:"34465");

  script_name(english:"F5 Networks rsync RCE");
  script_summary(english:"Checks for writeable rsync modules.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a rsync daemon that allows a user to upload
arbitrary files.");
  script_set_attribute(attribute:"description", value:
"The rsync daemon on the remote F5 Networks host is affected by an
authentication bypass vulnerability when configured in failover mode.
An unauthenticated, remote attacker can exploit this, via a cmi
request to the ConfigSync IP address, to read or write arbitrary
files.

Nessus was able to confirm that a module on the remote rsync daemon
allows writing files to the root of the file system. An attacker can
overwrite '/root/.ssh/authorized_keys' and obtain ssh access, allowing
the execution of arbitrary code with the privileges of the root user.");
  # http://support.f5.com/kb/en-us/solutions/public/15000/200/sol15236.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c5d7c6b5");
  # http://www.security-assessment.com/files/documents/advisory/F5_Unauthenticated_rsync_access_to_Remote_Root_Code_Execution.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7c390e25");
  script_set_attribute(attribute:"solution", value:
"Disable the rsync daemon.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("rsync_writeable.nasl");
  script_require_ports("Services/rsyncd", 873);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");
include("string.inc");
include("rsync.inc");

port = get_service(svc:"rsyncd", default:873, exit_on_fail:TRUE);

modules = get_kb_list_or_exit("rsyncd/" + port + "/writeable/*");

cmi = FALSE;
csync = FALSE;

if (!isnull(modules))
{
  foreach module (modules)
  {
    name = base64_decode(str:module);
    if (name == "cmi") cmi = TRUE;
    else if (name == "csync") csync = TRUE;
  }
}

if (!cmi && !csync) audit(AUDIT_LISTEN_NOT_VULN, "Rsync daemon", port);

# connect and get a file to ensure this is F5
csync_version_file = NULL;
cmi_version_file = NULL;

if (cmi)
{
  soc = rsync_init(port:port);
  if (soc)
  {
    version_file = rsync_get_file(socket:soc, module:"cmi", file_name:"VERSION");
    if ("Product: BIG-IP" >< version_file ||
        "Product: EM" >< version_file ||
        "Product: BIG-IQ" >< version_file)
    {
      cmi_version_file = version_file;
    }
    close(soc);
  }
}

if (csync)
{
  soc = rsync_init(port:port, exit_if_fail:TRUE);
  if (soc)
  {
    version_file = rsync_get_file(socket:soc, module:"csync", file_name:"VERSION");
    if (
      "Product: BIG-IP" >< version_file ||
      "Product: EM" >< version_file ||
      "Product: BIG-IQ" >< version_file
    ) csync_version_file = version_file;

    close(soc);
  }
}

if (!isnull(cmi_version_file) || !isnull(csync_version_file))
{
  if (report_verbosity > 0)
  {
    report = "";
    if (!isnull(cmi_version_file))
    {
      report += 
        '\n' + "Nessus was able to download VERSION from the writeable 'cmi' Rsync module: " +
        '\n' +
        '\n' + cmi_version_file;
    }
    if (!isnull(csync_version_file))
    {
      report += 
        '\n' + "Nessus was able to download VERSION from the writeable 'csync' Rsync module :" +
        '\n' + 
        '\n' + csync_version_file;
    }

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "F5 Networks");
