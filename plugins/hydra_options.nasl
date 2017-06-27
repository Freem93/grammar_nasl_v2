#TRUSTED 3ca4fbdc98c16e785cb8b5d672085270e523a54fc01de3d41f542b9350990ca147b2c479b3be550ba5321f98c2d6657bb554527c850476c67b2e8d6eb3410636f34541b4514c0c1ca6caeff5ada74245db3a3f816ce673dcd1a953dc5aecb15cafd356728af06d15c841ce3330e8c0da28779c1a214b956af1c795b6d68b3dd805ba6803913b2955adc9a03cd25568f6377d7077d4dc642dfecb590fa523ffecfc42b4b81163200fc836f951bdf6a2cbf2665b6a80e38fd38b2db694b098ce168d33fdf1f789704c9930307b45ebc839ef08b72d8296f7dd0388f4f349ae44a80753375a9149aa71f792e66a7c5e64b13c85fc6427f28ed1658af2d34d5e0282c7f87dd2753bde90e87b96085435a284648736e11936921918dd05609e9ad5304c46dc060d5d309160dab80bb12eb77f69ff1c8e196d1af0ecbadf287ec0e7dce829c847e3c940c68b67634ffd38fae6b776a9356c81e4809dbb5618a77a070a9cfff9eec15012f18f90ecaf6c0d3f9becb86fb65d71f26c704d6b8a7d07ada8de70eb5b3d7270fe7d314d78245641be2b962649cc994620ccc37544123417acda12f2fe3837aa327f07ae19518ed7440a842280e0b92e8b63984cb7bf5dbddd3c173e2970b1a13449209e340bf486f29242f174228bb8d1aaa7301b6decceb274015753fe2f63c2b71c96ddeb2c04d92e4faea4dec050dd08bd56bac4a26ab6
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("script_get_preference_file_location")) exit(0);
if (!find_in_path("hydra")) exit(0, "Hydra was not found in '$PATH'.");

include("compat.inc");

if (description)
{
 script_id(15868);
 script_version("1.19");
 script_set_attribute(attribute:"plugin_modification_date", value:"2015/10/13"); 

 script_name(english:"Hydra (NASL wrappers options)");
 script_summary(english:"Brute force authentication protocols");
 
 script_set_attribute(attribute:"synopsis", value:
"This plugin is used to set options for Hydra.");
 script_set_attribute(attribute:"description", value:
"This plugin sets options for the Hydra tests.  Hydra finds passwords
by brute force. 

To use the Hydra plugins, enter the 'Logins file' and the 'Passwords
file under the 'Hydra (NASL wrappers options)' advanced settings
block.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/01");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_MIXED_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");

 script_add_preference(name: "Always enable Hydra (slow)", type:"checkbox", value: "no");
 script_add_preference(name: "Logins file : ", value: "", type: "file");
 script_add_preference(name: "Passwords file : ", value: "", type: "file");
 script_add_preference(name: "Number of parallel tasks :", value: "16", type: "entry");
 script_add_preference(name: "Timeout (in seconds) :", value: "30", type: "entry");
 script_add_preference(name: "Try empty passwords", type:"checkbox", value: "yes");
 script_add_preference(name: "Try login as password", type:"checkbox", value: "yes");
 script_add_preference(name: "Exit as soon as an account is found", type:"checkbox", value: "no");
 script_add_preference(name: "Add accounts found by other plugins to login file", type:"checkbox", value: "yes");

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

function mk_login_file(logins)
{
  local_var	tmp1,tmp2, dir, list, i, u;
  if ( NASL_LEVEL < 2201 )
  {
    display("NASL_LEVEL=", NASL_LEVEL, " - update your Nessus engine!");
    return logins; # fwrite broken
  }
  dir = get_tmp_dir();
  if (! dir)
  {
    display("Could not get tmp dir.");
    return logins;	# Abnormal condition
  }
  dir += '/';
  for (i = 1; TRUE; i ++)
  {
    u = get_kb_item("SMB/Users/"+i);
    if (! u) break;
    list = strcat(list, u, '\n');
  }
# Add here results from other plugins
  if (! list) return logins;
  tmp1 = strcat(dir, 'hydra-'+ get_host_ip() + '-' + rand());
  tmp2 = strcat(dir, 'hydra-'+ get_host_ip() + '-' + rand());
  if (fwrite(data: list, file: tmp1) <= 0)	# File creation failed
  {
    display("Could not write file ", tmp1, ".");
    return logins;
  }
  if (! logins) return tmp1;
  pread(cmd: "sort", argv: make_list("sort", "-u", tmp1, logins, "-o", tmp2));
  unlink(tmp1);
  return tmp2;
}

if ("yes" >< thorough_tests)
  set_kb_item(name: "/tmp/hydra/force_run", value: TRUE);
else
{
 p = script_get_preference("Always enable Hydra (slow)");
 if ("yes" >< p)
   set_kb_item(name: "/tmp/hydra/force_run", value: TRUE);
 else
    exit(0, "Hydra scripts will not run unless the 'Perform thorough tests' setting is enabled or 'Always enable Hydra' is set.");
}

if ( ! script_get_preference("Passwords file : ") )
  exit(0, "No passwords file is provided.");
p = script_get_preference_file_location("Passwords file : ");
if (!p ) exit(0, "Hydra passwords file does not exist or is empty.");
if ( NASL_LEVEL >= 5000 )
{
  # Decipher the file
  mutex_lock(SCRIPT_NAME);
  if ( get_kb_item("/tmp/hydra/converted_pw") == NULL )
  {
    b = fread(p);
    fwrite(data:b, file:p);
    set_kb_item(name:"/tmp/hydra/converted_pw", value:TRUE);
  }
  mutex_unlock(SCRIPT_NAME);
}

set_kb_item(name: "Secret/hydra/passwords_file", value: p);

# No login file is necessary for SNMP, VNC and Cisco; and a login file 
# may be made from other plugins results. So we do not exit if this
# option is void.
a = script_get_preference("Add accounts found by other plugins to login file");
if (script_get_preference("Logins file : ") )
  p = script_get_preference_file_location("Logins file : ");
else
  p = NULL;


if ( p != NULL && NASL_LEVEL >= 5000 )
{
  # Decipher the file
  mutex_lock(SCRIPT_NAME);
  if ( get_kb_item("/tmp/hydra/converted_lg") == NULL )
  {
    b = fread(p);
    unlink(p);
    fwrite(data:b, file:p);
    set_kb_item(name:"/tmp/hydra/converted_lg", value:TRUE);
  }
  mutex_unlock(SCRIPT_NAME);
}

if ("no" >!< a) p = mk_login_file(logins: p);


set_kb_item(name: "Secret/hydra/logins_file", value: p);

p = script_get_preference("Timeout (in seconds) :");
t = int(p);
if (t <= 0) t = 30;
set_kb_item(name: "/tmp/hydra/timeout", value: t);

p = script_get_preference("Number of parallel tasks :");
t = int(p);
if (t <= 0) t = 16;
set_kb_item(name: "/tmp/hydra/tasks", value: t);

p = script_get_preference("Try empty passwords");
if ( "yes" >< p )
  set_kb_item(name: "/tmp/hydra/empty_password", value: TRUE);

p = script_get_preference("Try login as password");
if ( "yes" >< p )
 set_kb_item(name: "/tmp/hydra/login_password", value: TRUE);

p = script_get_preference("Exit as soon as an account is found");
if ( "yes" >< p ) 
 set_kb_item(name: "/tmp/hydra/exit_ASAP", value: TRUE);


# Collect some info about the installed version of Hydra.
results = pread(cmd:"hydra", argv:make_list("hydra"), nice:5);
foreach line (split(results, keep:FALSE))
{
  # - version.
  v = eregmatch(string:line, pattern:'^[ \t]*Hydra v([0-9][^ \t]+)[ \t]');
  if (!isnull(v))
  {
    set_kb_item(name:"Hydra/version", value:v[1]);
    continue;
  }

  # - syntax line (to diagnose problems).
  v = eregmatch(string:line, pattern:'^[ \t]*Syntax[ \t]*:');
  if (!isnull(v))
  {
    set_kb_item(name:"Hydra/syntax", value:line);
    continue;
  }

  # - supported services.
  v = eregmatch(string:line, pattern:'^[ \t]*service[ \t]+.*Supported protocols[ \t]*:[ \t]+(.+)$');

  # Newer versions of Hydra have moved the supported services line
  if (empty_or_null(v))
  v = eregmatch(string:line, pattern:'^[ \t]*Supported services[ \t]*:[ \t]+(.+)$');

  if (!isnull(v))
  {
    svcs = v[1];
    set_kb_item(name:"Hydra/services", value:svcs);

    svcs = str_replace(find:"ftp[s]", replace:"ftp ftps", string:svcs);
    svcs = str_replace(find:"http[s]-{head|get}", replace:"https-head https-get http-head http-get", string:svcs);
    svcs = str_replace(find:"http-{head|get}", replace:"http-head http-get", string:svcs);
    svcs = str_replace(find:"http[s]-{get|post}-form", replace:"https-get-form https-post-form http-get-form http-post-form", string:svcs);
    svcs = str_replace(find:"http-{get|post}-form", replace:"http-get-form http-post-form", string:svcs);
    svcs = str_replace(find:"ldap3[-{cram|digest}md5]", replace:"ldap3 ldap3-crammd5 ldap3-digestmd5", string:svcs);
    svcs = str_replace(find:"mysql(v4)", replace:"mysql", string:svcs);

    foreach svc (split(svcs, sep:" ", keep:FALSE))
    {
      set_kb_item(name:"/tmp/hydra/service/"+svc, value:TRUE);
    }
    continue;
  }
}
