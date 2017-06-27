#TRUSTED 38834d6df5f7c4907029914f436f66d5a21239c6ddc22f7366e8c9a6fbb4bb91bd3b6ac737262235b6d7f8aeefffa57aac0e0112fb583b4b0bcfade47367afa2f6246615d52c4944fda095a3e81041dce52636ad3bcca55641532c37c465cd1d0644a832469db6ec8240b7cb2af7de9c88ced0c1951fbad85ce83acc53c2610683d4e85a3d0056f23f386c827e0ba1caf42ddaa83ff310073385c85d7706241907fa89371e2baae8cba933089474cd97cff8d6d2a57cd996f3479b4d5ba965548df16facbed073426b687b7a1a888ddae336b8c6141ae9d54f5d6559b6aa97bba1ba2108e57bd545383b2a544d9c6891aab860eb8f743b3c7584461ae64cc354e8a94f5a21a7c8f3fd72cb9233e01f791f5c71bbd5436ec86062e7c1e4b1a5e92cea345812b5fdc6da6b45d1c5fff840b296526e200e34b6f8430cbebda210cfc4046ff11090efcb1cb969a56a0752f4834a0af85dda1df6c6123fad837a86c37b4d96e1619023b7b6a42414d94020f6f032a03fef6e66e412d53367521cf7a4b570b8efef2b243613147c72ccf0753bf8c4ab320916a151898164a35887753634cc7a6715e7e432823971bab99ac8ed5a49e0ac47f539e6384bd02c1fd86420e4f70c10ab30d29bb7f86e418866eb58f885ffa1933d930b5cfd06d7cdc096733af13a1c36aa180331c570db54faed24937ada417ba53087ea3fba7d196c0e82
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(90707);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/04/26");

  script_name(english:"SSH SCP Protocol Detection");
  script_summary(english:"Detects SCP support over SSH.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host supports the SCP protocol over SSH."
  );
  script_set_attribute(
    attribute:"description",
    value:"The remote host supports the Secure Copy (SCP) protocol over SSH."
  );
  script_set_attribute(attribute:"see_also",value:"https://en.wikipedia.org/wiki/Secure_copy");
  script_set_attribute(
    attribute:"solution",
    value:"n/a"
  );
  script_set_attribute(attribute:"risk_factor",value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/26");
  script_set_attribute(attribute:"plugin_type",value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");

  exit(0);
}

include("global_settings.inc");
include("ssh_func.inc");
include("ssh_scp_func.inc");
include("misc_func.inc");
include("obj.inc");
include("audit.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

sock_g = ssh_open_connection();
if (!sock_g) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
info_t = INFO_SSH;

port = kb_ssh_transport();

if(!ssh_scp_init()) audit(AUDIT_FN_FAIL, 'ssh_scp_init');

ssh_scp_pull_file(location:rand_str(length:50));

ssh_err = tolower(get_ssh_error());

if('no such file or directory' >< ssh_err && "scp warning" >< ssh_err)
{
  set_kb_item(name:'SSH/SCP/' + port + '/Supported', value:TRUE);
  security_note(port);
}
else
{
  set_kb_item(name:'SSH/SCP/' + port + '/Supported', value:FALSE);
  exit(0, 'SCP not supported over ssh server on port ' + port + '.');
}
