#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45545);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2014/02/04 02:39:10 $");

  script_cve_id("CVE-2009-4510");
  script_bugtraq_id(39389);
  script_osvdb_id(63834);

  script_name(english:"TANDBERG Video Communication Server Static SSH Host Keys");
  script_summary(english:"Checks SSH fingerprint");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SSH service uses a static host key."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote device appears to be a TANDBERG Video Communication Server
(VCS), an appliance supporting interoperation of video conferencing
and unified communications devices. 

The fingerprint for the SSH service running on this device matches
that of the host key distributed with some versions of the VCS
firmware. 

Knowing this, a remote attacker may be able to impersonate or conduct
man-in-the-middle attacks and gain shell access to the affected
device."
  );
  script_set_attribute(attribute:"see_also", 
    value:"http://www.vsecurity.com/resources/advisory/20100409-2/"
  );
  script_set_attribute(attribute:"see_also", 
    value:"http://www.securityfocus.com/archive/1/510654"
  );
  script_set_attribute(attribute:"solution", 
    value:
"Generate a new SSH host key and use it in place of the current one. 
Then upgrade to VCS firmware version 5.1.1 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/14");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencie("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");


port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);
if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");


fingerprint = get_kb_item("SSH/Fingerprint/ssh-dss/"+port);
if (!fingerprint) exit(0, "There is no DSA host key associated with the SSH service on port "+port+".");


known_fingerprint = "4953bf942ad70c3f4829f75b5dde89b8";
if (tolower(fingerprint) == known_fingerprint)
{
  if (report_verbosity > 0)
  {
    fingerprint = ereg_replace(pattern:"(..)", replace:"\1:", string:fingerprint);
    fingerprint = substr(fingerprint, 0, strlen(fingerprint)-2);

    report = 
      '\nThe DSA host key used by this service has been fingerprinted as :\n' +
      '\n' +
      '  ' + fingerprint + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);  
}
else exit(0, "The DSA host key associated with the SSH service on port "+port+" does not match the default used by VCS.");
