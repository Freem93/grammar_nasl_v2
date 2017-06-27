#TRUSTED 95f0f9dfcc4804c16717575f8e2da6b795ff7a4bff4fb1c9b8bbb5cd20b54b63bff30893d47fddddd0660723adf6c2117c3f2a61d262d259c30e058ce062dd90c51545adedfe655c2f4a86e7b538b4438f91ae5a732d40d870a240ad0fca0496bbfbdd24f419a929dfc1032539d1ac794ef36eb7ccd8aab64229d0d24362d38677072ef70380e7f819babd641b70f726b45930996ca3b7512f9764e85a1bd55fa2a7d71f0a543b48e43c72a8c3c067ddeefaca2f0071a391914ee92d1e615876863f41abf9a81a7d11f688aa03b39f177ef54cfa53f119a0080c77bf7e59f6b18552665cfe5710a04a3746f80103e24ed3129f03dbb3d45940717a5f844b79c973143f98a17bb6fef6efbb02701cf16803e753dc2473a25c531b5b81eeba34a7794c9e3928ba6da96b1b119795fc1f0996816c3b8c664c094fc9706e36e90eb377d1cb49cec9f2444de7ab48e4d9cdc9aa2408345091976e8bab53874f263c67715522ec032e3fd58bc0c53801085f674e876a97fe30f897fba96c17d9728f4b8f90806659bfbeabea9883d12b5f08168e58d97f3f3366d6e5b05a6aa8a25abb8c4df213d8246674b81bf9bf8372cfb6456f4b2687e2648f3a253d1e8fa933aab2c0372333a0fc3e373a7e5dec3dd2ce70452fc6189868b184b0577660f0e006e04abf9599284c38bfc4a049f33bca52be7689882af05370fb5002260387f682
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);


include("compat.inc");


if (description)
{
  script_id(54832);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2012/04/06");

  script_name(english:"Mac OS X Mac Defender Malware Detection");
  script_summary(english:"Checks for evidence of MacDefender");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Mac OS X host appears to have been compromised."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Using the supplied credentials, Nessus has found evidence that a fake
antivirus software named Mac Defender (alternatively, MacDefender,
MacGuard, MacProtector or MacSecurity) is installed on the remote Mac
OS X host. 

The software is typically installed by means of a phishing scam
targeting Mac users by redirecting them from legitimate websites to
fake ones that tell them their computer is infected with a virus and
then offers this software as a solution. 

Once installed, the malware will perform a 'scan' that falsely
identifies applications such as 'Terminal' or even the shell command
'test' ('[') as infected and will redirect a user's browser to porn
sites in an attempt to trick people into purchasing the software in
order to 'clean up' their system."
  );
  # http://nakedsecurity.sophos.com/2011/05/02/mac-users-hit-with-fake-av-when-using-google-image-search/
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?abf43744"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT4650"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Follow the steps in Apple's advisory to remove the malware."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");


packages = get_kb_item_or_exit("Host/MacOSX/packages");


apps = make_list(
  "MacDefender",
  "MacGuard",
  "MacSecurity",
  "MacProtector",
  "MacShield"
);

report = '';
foreach app (apps)
{
  # Look for a couple of different indicators.
  info = make_array();

  # - application directory.
  appdir = '/Applications/' + app + '.app';
  cmd1 = 'test -d \'' + appdir + '\' && ls -ld \'' + appdir + '\'';

  # - active process.
  #   nb: this just lists all processes.
  cmd2 = 'ps -axwww -o user,pid,command';

  # - login items.
  #   nb: this just lists all login items.
  cmd3 = '(echo ; /usr/bin/dscl  . -readall /Users NFSHomeDirectory UniqueID) |while read sep; do read Home; read Record; read UniqueID; UniqueID=`echo $UniqueID |awk \'{print $2}\'`; test "$UniqueID" -gt 499 && echo $Record:|awk \'{print $2}\' && Home=`echo $Home|awk \'{print $2}\'` && test -f "$Home"/Library/Preferences/com.apple.loginitems.plist  && /usr/bin/defaults read "$Home"/Library/Preferences/com.apple.loginitems; done';

  results = exec_cmds(cmds:make_list(cmd1, cmd2, cmd3), exit_on_fail:FALSE);
  if(!isnull(results))
  {
    if (strlen(results[cmd1]) >= strlen(app) ) 
    {
      info["Application directory"] = appdir;
    }

    if (!strlen(results[cmd2])) exit(1, "Failed to get a list of active processes.");
    else
    {
      matches = egrep(pattern:'('+app+'\\.app/|MacOS\\/'+app+')', string:results[cmd2]);
      if (matches)
      {
        info["Active process"] = join(matches, sep:"");
      }
    }

    if (strlen(results[cmd3]))
    {
      user = "";
      foreach line (split(results[cmd3], keep:FALSE))
      {
        match = eregmatch(pattern:'^/Users/([^:]+):', string:line);
        if (match) user = match[1];

        match = eregmatch(pattern:'^ +Path = "(.+/'+app+'\\.[^"]*)"', string:line);
        if (match && user) info["Login item"] += user + ' (' + match[1] + ')\n';

        if (ereg(pattern:'^} *$', string:line)) user = '';
      }
    }

    if (max_index(keys(info)))
    {
      max_item_len = 0;
      foreach item (keys(info))
      {
        if (strlen(item) > max_item_len) max_item_len = strlen(item);
      }

      report += '\n  - ' + app + ' : ';
      foreach item (sort(keys(info)))
      {
        val = info[item];
        val = str_replace(find:'\n', replace:'\n'+crap(data:" ", length:max_item_len+11), string:val);
        val = chomp(val);

        report += '\n      o ' + item + crap(data:" ", length:max_item_len-strlen(item)) + ' : ' + val;
      }
      report += '\n';
    }
  }
}

if (report)
{
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet') security_hole(port:0, extra:report);
  else security_hole(0);
}
else exit(0, "MacDefender is not installed.");
