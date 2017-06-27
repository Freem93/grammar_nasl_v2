#TRUSTED a0eb94b3e3b5f87b510c882c4a05b9655364b15969c758bf3b7b1e2b4faaa67f0017c7f24b4d433b0633df7be2944003445c530149d7721d7c7723f09b434bfe332feb86d838b5776046ec0b7e532dfddb3003a27843b16f1471f56b6a8d6f63cf0c541e3509948a527e1da59738cbbc37664f5fe0722410b46afa656e21781e44c742d547a2ddedd6f66d898617abf6143523f7f54e89224f93314eb863a976660c006539990bfad6c13fb11f39331e87e05d4fe98d910f2bf0ca970dbbcac2d7524b6d155c96a5941375f43241cae35471e8c676dc5c4d896907d00c8e3747a7189edf12d340a3a5b5549fd96791dd20d330fbd8313c042530aa843ab1c7067316c2ad1b0f27d27f74d9ac0da02bc4d9a714c077ff7267dd11246edbdfe827e445d758e6807e1812407516efcf10909d904d82e7b73f425330f29fd2f672ac7a142dc3302a4fa06e9f30633c71f40d8acee63c2a7834f4c2d9d11373b2cf49bf19fc4fbb21f13bb6258b648a599af997d7ed5939c60d86d1a07d53d21d3f50f803c97532c7d5037105a3563acc8a5f02c1e253688f5b919779510feb4c17bcdceb1d853c7b3f798d81d6d643682cab28cfc9bece36f41413f0534c97529cc50e7c85825aa0ed3aa047965bbb3c539a491d10615817a491e4095a5fdc4e683937a6ed7b9a4f43a8e7277da43898fc68c6ab778601e4405351bc844a6fb78ae0
###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# @NOGPL@
#
###
if (!defined_func("nasl_level") || nasl_level() < 5000) exit(0, "Nessus older than 5.x");

include("compat.inc");

if (description)
{
  script_id(64286);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/07/16");

  script_name(english:"Palo Alto Networks PAN-OS Settings");
  script_summary(english:"Set Palo Alto authentication settings to perform authenticated compliance checks.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin configures the Palo Alto settings.");
  script_set_attribute(attribute:"description", value:
"This script initializes the credentials used for Palo Alto Firewall. 

To set the credentials, edit your scan policy and go to the
'Credentials' section.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/21");

  script_set_attribute(attribute:"plugin_type", value:"settings");
  script_end_attributes();

  script_family(english:"Settings");
  script_category(ACT_SETTINGS);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_add_preference(name:"Palo Alto Username : ", type:"entry", value:"");
  script_add_preference(name:"Palo Alto Password : ", type:"password", value:"");
  script_add_preference(name:"Palo Alto Port : ", type:"entry", value:"443");
  script_add_preference(name:"SSL : ", type:"checkbox", value:"yes");
  script_add_preference(name:"Verify SSL Certificate : ", type:"checkbox", value:"no");

  exit(0);
}

username   = script_get_preference("Palo Alto Username : ");
password   = script_get_preference("Palo Alto Password : ");
port       = script_get_preference("Palo Alto Port : ");
ssl        = script_get_preference("SSL : ");
verify_ssl = script_get_preference("Verify SSL Certificate : ");

if (!username || !password)
  exit(0, "Palo Alto authentication is not configured.");

set_kb_item(name:"Secret/Palo_Alto/Firewall/Login",    value:username);
set_kb_item(name:"Secret/Palo_Alto/Firewall/Password", value:password);

if (!port) port = 443;

set_kb_item(name:"Host/Palo_Alto/Firewall/Port", value:port);

if (ssl && "yes" >< ssl)
  set_kb_item(name:"Host/Palo_Alto/Firewall/ssl", value:TRUE);
else
  set_kb_item(name:"Host/Palo_Alto/Firewall/ssl", value:FALSE);

if (verify_ssl && "yes" >< verify_ssl)
  set_kb_item(name:"Host/Palo_Alto/Firewall/verify_ssl", value:TRUE);
else
  set_kb_item(name:"Host/Palo_Alto/Firewall/verify_ssl", value:FALSE);

# If the superadmin credentials were supplied, ensure that they are
# added to SSH credentials as well.
if (username =~ "^admin$")
{
  ssh_inserted = FALSE;
  # Iterate through SSH credentials until you find an empty slot.
  # Look at primary creds first and set those if empty.
  if (isnull(get_kb_item("Secret/SSH/login")))
  {
    set_kb_item(name:"Secret/SSH/login", value:username);
    set_kb_item(name:"Secret/SSH/password", value:password);
    ssh_inserted = TRUE;
  }
  else if (isnull(get_kb_item("Secret/SSH/password")) && isnull(get_kb_item("Secret/SSH/privatekey")))
  {
    replace_kb_item(name:"Secret/SSH/login", value:username);
    set_kb_item(name:"Secret/SSH/password", value:password);
    ssh_inserted = TRUE;
  }
  else
  {
    for (i = 0; i < 5; i++)
    {
      if (isnull(get_kb_item(strcat("Secret/SSH/", i, "/login"))))
      {
        set_kb_item(name:strcat("Secret/SSH/", i, "/login"), value:username);
        set_kb_item(name:strcat("Secret/SSH/", i, "/password"), value:password);
        ssh_inserted = TRUE;
        break;
      }
    }
  }
  if (ssh_inserted) exit(0);
  else exit(0, "SSH credentials not inserted, no empty slot found.");
}
