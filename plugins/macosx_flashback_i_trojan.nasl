#TRUSTED 7db690fecc823bdf9452238661c580afd4e6b56ef60106ae3bd4836e4faf0512ea7c023309075714e5745177d1f8a77ca40d20d7e6e674ad547eaa9594c6a7bafc9bdf2f11fac7bf10dce313566dbcfc0bea590c3432083262334536e034355320a5cdc1e56bb343c960ee1e0e64f48b132ad93e7fbe5f8eaf54be850c6ade683f94c5ef5c22ab40a6eeb6776f76ae2f3bfac71dddeb132323e26f04700ca9a6b0b5dbe5ec6118126a8af54c31baa70d887e8ff2910fd04cf534e922ba874d48eb2a5f1a308e16cbf433eb0d67866c07b99b3182652095fadb4e27561302fe6e4a91d0b20f757ae7b8bb2d91eeccda8763f815615b45435762b9ba82a7f4aa660a613a7fd11b5774d0650328017267d9201a6287da8e2d5a1fe82d202116b42c91dfab9db1de41d1cb55009d438fb9c11dfcc0e5a7bc39e4d23e69ddefe05049d101a3b33440f95aeac826d05f957f9b25587b26e1aa73e3efa469698eb2e62c30061619d21314340882464a319141d68b8a2c85eaed71f6bda5626bfe8f50280d8328fd4312f28c7435fd11bc44987c85799dd0b4b172f17b51e46202e1f754b66f899f9cfe2f4f437235e0afc02e5d17cfefea965c601a4a0730d3ab850e8fd2778608f4ac09c43950e6fa2d10dc91f6ae67aaabfdd00e630361e9dce45c4a403c6cda0d2514f9917f3f109c39b32a2850d9d78abae29780873344011b939d
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);


include("compat.inc");


if (description)
{
  script_id(58619);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2012/04/24");

  script_name(english:"Mac OS X OSX/Flashback Trojan Detection");
  script_summary(english:"Checks for evidence of Flashback");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Mac OS X host appears to have been compromised."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Using the supplied credentials, Nessus has found evidence that the
remote Mac OS X host has been compromised by a trojan in the
OSX/Flashback family of trojans. 

The software is typically installed by means of a malicious Java
applet or Flash Player installer.  Depending on the variant, the
trojan may disable antivirus, inject a binary into every application
launched by the user, or modifies the contents of certain web pages
based on configuration information retrieved from a remote server."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.f-secure.com/v-descs/trojan-downloader_osx_flashback_a.shtml"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.f-secure.com/v-descs/trojan-downloader_osx_flashback_b.shtml"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.f-secure.com/v-descs/trojan-downloader_osx_flashback_c.shtml"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.f-secure.com/v-descs/trojan-downloader_osx_flashback_i.shtml"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.f-secure.com/v-descs/trojan-downloader_osx_flashback_k.shtml"
  );
  # http://www.intego.com/mac-security-blog/new-flashback-variant-continues-java-attack-installs-without-password/
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?7f51a6ed"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Restore the system from a known set of good backups."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");


report = "";
foreach app (make_list("Safari", "Firefox"))
{
  cmd = strcat("defaults read /Applications/", app, ".app/Contents/Info LSEnvironment");
  res = exec_cmd(cmd:cmd);
  if (strlen(res) && "DYLD_INSERT_LIBRARIES" >< res)
  {
    libs = egrep(pattern:"DYLD_INSERT_LIBRARIES", string:res);
    libs = str_replace(find:'\n', replace:'\n                          ', string:libs);
    report += '\n  Command               : ' + cmd +
              '\n  DYLD_INSERT_LIBRARIES : ' + libs;
  }
}

homes = get_users_homes();
if (isnull(homes)) exit(1, "Failed to get list of users' home directories.");

foreach user (sort(keys(homes)))
{
  home = homes[user];
  if (home == "/var/empty" || home == "/dev/null") continue;

  cmd1 = strcat('defaults read "', home, '"/.MacOSX/environment DYLD_INSERT_LIBRARIES');
  cmd2 = strcat('ls "', home, '"/Library/LaunchAgents');
  cmd3 = strcat('ls -a1 "', home, '"/');
  res = exec_cmds(cmds:make_list(cmd1, cmd2, cmd3));
  if (!isnull(res))
  {
    if (
      strlen(res[cmd1]) &&
      "DYLD_INSERT_LIBRARIES" >< res[cmd1] &&
      "DYLD_INSERT_LIBRARIES) does not exist" >!< res[cmd1]
    )
    {
      libs = egrep(pattern:"DYLD_INSERT_LIBRARIES", string:res);
      libs = str_replace(find:'\n', replace:'\n                          ', string:libs);
      report += '\n  User                  : ' + user +
                '\n  Command               : ' + cmd +
                '\n  DYLD_INSERT_LIBRARIES : ' + libs;

    }
    if (strlen(res[cmd2]) && "com.java.update.plist" >< res[cmd2])
    {
      report += '\n  User : ' + user +
                '\n  File : ' +  home + '/Library/LaunchAgents/com.java.update.plist';
    }
    if (strlen(res[cmd3]) && res[cmd3] =~ "^\.jupdate$")
    {
      report += '\n  User : ' + user +
                '\n  File : ' +  home + '/.jupdate';
    }
  }
}


if (report)
{
  if (report_verbosity > 0) security_hole(port:0, extra:report);
  else security_hole(0);
  exit(0);
}

exit(0, "No evidence of OSX/Flashback was found.");
