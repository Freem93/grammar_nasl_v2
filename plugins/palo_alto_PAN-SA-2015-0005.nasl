#TRUSTED 4f937555ac1886995d15a7eb52fbf5ecb905f498892b4d53f935f5c05778d53a773bd9b604241d0b166af9afddfe2e2cac6044b89be5e25ba7c1717710f0adb74de59d0bc0983722b76f7c4be3de30384ce5afbb7d77c646e4ec8177abdb07f6037a76ab5611d8f71d3020b82b47e1666615fd2b1da40e1ef814aac7453da42e94cd8d84191ab3158a4953e42c4719d692565fa22e25aee395c1768ea051c927d8bcfe17f70e02d2b87b3eec8b38eae61024ee3771a65406f30ab1afa1666f213327d89a060ae5f63121bfc530e5989b795790c1652464439aa11ebefb794fe616edf9baa85e3c39bf5521a3f593d417741d39efdfadd1b76c198574ccdad6eda92bd10f5feb8ac51e700a1ff237314fc32fbcd157a8a75626fe6164cead725b21bf67195454b19de8353a3ce3fa5f5ece8304746b58f36eb648ff1e971c2d0acdb9481fb3641432d47c38e25b98620104a65a25b97a373aa4ca6b045ada254866ea21971e7f65265cbd5155743ea05b9300fd756ead83b5871b92b8d45b8812fb5bb17920aaa8a29b9011a520a93f0720e418238186648314ec07fc7549f40a5ae0fd2195ae9a3500f5a9d95b8e58dab4da99ddce4289650e0699d76ad56c4e6106db270d6e82e910df3a36b289353f449e68faf80921f38936ab7e148c4bca1aba9a0a4a905b3901b275099c9072dcbb0cbc1b81e892d35c4b76b35a504daf
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85535);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/05/03");

  script_osvdb_id(125404);

  script_name(english:"Palo Alto Networks PAN-OS 7.0.0 LDAP Authentication Bypass (PAN-SA-2015-0005)");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an authentication security bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Palo Alto Networks PAN-OS version 7.0.0. It
is, therefore, affected by an unspecified flaw in the LDAP
authentication process. A remote attacker can exploit this to bypass
authentication checks presented by the captive portal component or the
device management interfaces.");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/32");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks PAN-OS 7.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_dependencies("palo_alto_version.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/Palo_Alto/Firewall/Version", "Host/Palo_Alto/Firewall/Full_Version");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");

if (!get_kb_item("Host/local_checks_enabled"))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

app_name = "Palo Alto Networks PAN-OS";
version = get_kb_item_or_exit("Host/Palo_Alto/Firewall/Version");
full_version = get_kb_item_or_exit("Host/Palo_Alto/Firewall/Full_Version");
has_ldap = FALSE;
fix = FALSE;

# Advisory is very specific : only 7.0.0 is affected
if(version == "7.0.0")
  fix = "7.0.1";
else
  audit(AUDIT_INST_VER_NOT_VULN, app_name, full_version);

# If we're paranoid, check for an LDAP profile on the device
if(report_paranoia < 2)
{
  cmd = "show config running xpath shared/authentication-profile | match 'ldap'";
  buf = ssh_open_connection();
  if(!buf)
    audit(AUDIT_FN_FAIL, "ssh_open_connection");
  buf = ssh_cmd(cmd:cmd, nosh:TRUE, nosudo:TRUE, noexec:TRUE, no53:TRUE);
  if("ldap" >< buf)
    has_ldap = TRUE;
  ssh_close_connection();
}
else # Otherwise assume the risk of FP
  has_ldap = TRUE;

if(fix && has_ldap)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + full_version +
      '\n  Fixed versions    : ' + fix +
      '\n';
    security_hole(extra:report, port:0);
  }
  else security_hole(0);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, app_name, full_version);
