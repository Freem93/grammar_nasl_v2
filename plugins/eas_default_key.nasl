#TRUSTED 44a26ecbd0c28eae59db126cacbda6964f898609b114deb42c9d3ba1aad7891014cddeae639a83e6c5824e02ba70f39155fcafa746b00bfccd662de5b06d945e2687c3ed5d49c3f2496625c8a382eb68d66cb6a7053b1c92881b02dc1cd4648bf109213e169acfb3a3b979e18441fd37b3c624faf037382581c4a346c175466bbc035406ba6e750c7284e8e7c0d489b6fcc109631846685f22a6fd19cedab9f585b3f32a0125b3b0f67fef810d6bd67a2e5f14ec5eeed193b6544136520b23471c23f718c6a50621eba1f7abd5d324e092b38bde1a423303292e3b7ab3440a7629d69a86f51457884ceaea03ee1136b3c7bde2c34d739c6984f4aaffd4ba617fea035206dc1012f92a0bfaba9cfb3feb4c9b128ba5459595bf9446356cd8e780b504e357d05f30d8df72b216aac72ff8446120ad19bc1f7ea35d6fc8dad2c32f11bfa506b77380238382ebff62b77a4ef076135651e55372c4c391955eb7171e2c507236d8270ab840f5ebe8c7355f759b87e04bf27b5118f3e8d1198e059a1d80916bfa6355433d1a13c2fd0361dc1e76cdb36a920b07b12df24b657269b0d59712c2b3c13f4d59abb13a6580b7fd81347d679fc5d6f751f114fb2bd3f689a2ae042a948607af4a6339152d9e20c733661212cf71e715c302713d8b5d006ec6888367301a7b972bf7888e22d7cd618f237b988345b6bc553259fec944e8b805
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69471);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2013/09/03");

  script_cve_id("CVE-2013-0137");
  script_bugtraq_id(60810);
  script_osvdb_id(94677);
  script_xref(name:"CERT", value:"662676");

  script_name(english:"Multiple Vendors EAS Authentication Bypass");
  script_summary(english:"Checks the authorized_keys2.dasdec file for the presence of the compromised key");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an authentication bypass 
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote EAS device permits root login using an SSH key with a 
publicly available private key. The private key was included in 
older copies of Monroe Electronics and Digital Alert Systems firmware.
A remote attacker with access to the private key can bypass 
authentication of the root user.");
  script_set_attribute(attribute:"solution", value:"Update to firmware version 2.0-2 or higher.");
  script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/662676");
  # http://www.informationweek.com/security/vulnerabilities/zombie-apocalypse-broadcast-hoax-explain/240157934
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0b8ed86f");
  # http://arstechnica.com/security/2013/07/we-interrupt-this-program-to-warn-the-emergency-alert-system-is-hackable/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dff79770");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:monroe_electronics:r189_one-net_eas");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:digital_alert_systems:dasdec_eas");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Services/ssh", 22);
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("ssh_func.inc");

if (!get_kb_item("Host/local_checks_enabled"))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

keygen_command = "test -f /root/.ssh/authorized_keys2.dasdec && ssh-keygen -l -f /root/.ssh/authorized_keys2.dasdec";
line_count_command = 'test -f /root/.ssh/authorized_keys2.dasdec && wc -l /root/.ssh/authorized_keys2.dasdec';
keygen_expected = "1024 0c:89:49:f7:62:d2:98:f0:27:75:ad:e9:72:2c:68:c3 ";

if ("Linux" >!< get_kb_item_or_exit("Host/uname"))
  audit(AUDIT_OS_NOT, "Linux");

ret = ssh_open_connection();
if (!ret)
  audit(AUDIT_SVC_FAIL, "SSH", kb_ssh_transport());

keygen_output = ssh_cmd(cmd:keygen_command, nosh:TRUE, nosudo:FALSE);

if (keygen_expected >< keygen_output)
{
  ssh_close_connection();
  
  vuln_report = NULL;
  if (report_verbosity > 0)
  {
    vuln_report = '\nFound the RSA public key with fingerprint "0c:89:49:f7:62:d2:98:f0:27:75:ad:e9:72:2c:68:c3" in the authorized keys file.\n';
  }

  security_hole(port:kb_ssh_transport(), extra:vuln_report);
  exit(0);
}

if (report_paranoia > 1)
{
  line_count_output = ssh_cmd(cmd:line_count_command, nosh:TRUE, nosudo:FALSE);
  ssh_close_connection();

  matches = eregmatch(pattern:"^([0-9]+) ", string:line_count_output);
  if (isnull(matches) || isnull(matches[1]))
    # This is set to 1 arbitrarily. It could just as well be set to 0.
    # It is set to something <=1 to pass the (... && line_count > 1) check below.
    # If we can't get a number out of the wc -l output, we can't advise the user to manually audit.
    line_count = 1;
  else
    line_count = int(matches[1]);

  if (line_count > 1)
  {
    audit_msg =
      " Note that Nessus checked only the first key in the authorized_keys2.dasdec file,
      yet the file has more than one line. Please manually audit this file.";
    exit(0, audit_msg);
  }
  else
    audit(AUDIT_HOST_NOT, "an affected EAS device");
}
else
{
  ssh_close_connection();
  audit(AUDIT_HOST_NOT, "an affected EAS device");
}
