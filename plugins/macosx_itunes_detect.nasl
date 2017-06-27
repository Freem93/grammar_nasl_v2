#TRUSTED 8f6f860bb840d02e0ef05ce11ac3f8b2716bddba79a1ca932693ae040895a68137540ddc7d273296bc87a64fed9e11f6942bcd531a3c195451a31088fa7b15bb7e3b9a521bf038c1d572a9a2b2f29a99d05971b05459b2d4bbe8a6a90aee2c4b8c82ac2efaf0052d6c3ec6d6180079c7c247389fe9d1e4dd2b50c73c08f4ee254aa5a31aafa7a107f4a1b8d604a37bc6a47766c4cc61a5d6250432055888fd67e33e05c4e94003479ced6eb441b32c3f2b6995c217c308df6a9d32422f92786a4654ce942f96343b3d4d436f7143c6be00666967623eb74b216691bdfe94edf3c5bb82814744d53cf101e5eb81615d1c337dfff0a3320bd9de0d59ac52080fc7898502c3f6cecd9a7cb8b9b428bcd47ac878b6b0399aaf652211252b0f3de6c5326a1b7b6d60cdf164313703b574346d699664318c6a69ffb722903debfe12b317efe625d72b9bde066e687051567fac3fd2333f79d38feb6517c71a7f80ab489fa728f523162acf415310b55677bcb768b81678e1e12a6f5faf9816be1ec4bb1140740917f42f145fdd4fb331f6ef061faf14e677bbf1ae310021cf689d9b0e337a01f3d47eeda09f82375260fdac9b0642d02c2fe5347302611c3801e14ad6980e8673985127c5ac7f50b3c24f657aa26bf6e24af3f00701145e0a4e771cc175a6cb96943cfe6f77b26ed0f91ff99fe75a6a54f661757a24de33a3fb48300f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25997);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_name(english:"iTunes Version Detection (macOS)");
  script_summary(english:"Check the version of iTunes.");

  script_set_attribute(attribute:"synopsis", value:
"Apple iTunes is installed on the remote macOS or Mac OS X host.");
  script_set_attribute(attribute:"description", value:
"Apple iTunes, a popular media player, is installed on the remote macOS
or Mac OS X host.");
  script_set_attribute(attribute:"solution", value:
"Ensure the use of this application complies with your organization's
acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None" );
  script_set_attribute(attribute:"plugin_publication_date", value: "2007/09/07");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");
  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");
  exit(0);
}

include("ssh_func.inc");
include("macosx_func.inc");
include("install_func.inc");
include("misc_func.inc");
include("global_settings.inc");
include("audit.inc");

cmd = GetBundleVersionCmd(file:"iTunes.app", path:"/Applications");
uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.*", string:uname) )
{
  if ( islocalhost() )
   buf = pread(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
   ret = ssh_open_connection();
   if ( ! ret ) exit(0);
   buf = ssh_cmd(cmd:cmd);
   ssh_close_connection();
  }
  if (buf !~ "^[0-9]") exit(1, "Failed to get version - '"+buf+"'.");

  vers = split(chomp(buf), sep:'.', keep:FALSE);

  register_install(
    app_name:"iTunes",
    path:"/Applications",
    version:string(int(vers[0]), ".", int(vers[1]), ".", int(vers[2])),
    cpe:"cpe:/a:apple:itunes");
}

report_installs(app_name:"iTunes");
