#TRUSTED 92314621c73ead6aee25deb00a66055c38567ee085d6d01177a0ca3669d67fe37354363c866ef8a66c6ce73a335dad016cac3428857740c751e77666b7ea092f79afd6f5e5b6e4762a7db625a890271ac78a4e4d1e5fc1e204ea197389a3bd24544ff9280e71dd7abcd1ae84ed884c587c2ea3af5901dc9894178940667a8f221a0a8b7709f5171f23589f0642e243900d435c8a828284033adcdbc3d80985d470c6dc293dcdfc24cb8a987fd6e203b56ef0997e1e1ed3ab1d7e5be5e7ba0775e4a874e76dd06f9e1478714243d77729c33747ae39c21326d151a522f60a453aa41485d996d26b1ba75f82f66cde26057f6e6d7a2bb98f7bc69fbbf9810ed6608ec19986a8315c1943778fa27b111fa8e7b9dbd706dc850d9c1339550e59216158cb72e9420a5ff4cb13e02c42d135e14afa0348241222a666afb2bfc680afeae5e66c077169c5f3d1d67b34da0767c27eccd41d2d513f406388b9bb1c8c94e95e019821caa9a5e79436ec2f80dfa0fde39a3c5421f1bff415e008eca5ca34de2d2f00f11b7743b26c91dd81878eada513e03cc3f028f770d97d60458e4816a954a999bff0b29bb7b86107db98ed48bb9c10dacdaf5fa5c6c4c4c3e30952aad7d7f9461e4e75e2d1643b522d0a63b1dcd960055eb27eea67e7af1fd408eef7dadb34901ed11dedf70e5992641aae3415686596f01202c77d02640023c856c029
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# path.inc
#
# Revision: 1.4
#

##
# Stores the list of lists / arrays that are operated on by path
# functions.
##
global_var _path_list;
_path_list = make_list();

##
# Stores the list of indexes in _path_list that are free.
##
global_var _path_freelist;
_path_freelist = make_list();

##
# Points to the first ID in the free list that is still free.
##
global_var _path_freelist_pos;
_path_freelist_pos = 0;

##
# Stores a list / array for fast access.
#
# @anonparam ds A data structure, an array or a list, to be stored and
#               managed by the path library.
#
# @return The ID for accessing the data structure with the path
#         library.
##
function path_store()
{
  local_var ds, id;

  # Sanity check argument.
  ds = _FCT_ANON_ARGS[0];
  if (isnull(ds))
    return NULL;

  # Try and find a slot for the data structure.
  if (_path_freelist_pos < max_index(_path_freelist))
  {
    # Put the data structure in an open slot.
    id = _path_freelist[_path_freelist_pos];
    _path_freelist_pos++;
  }
  else
  {
    # Create a new slot for the data structure.
    id = max_index(_path_list);
  }

  # Store the data structure.
  _path_list[id] = ds;

  return make_path(id);
}

##
# Delete a data structure by ID.
#
# @anonparam path The path to delete.
#
# @return TRUE if successful, FALSE otherwise.
##
function path_free()
{
  local_var id, pos;

  # Sanity check argument.
  id = _FCT_ANON_ARGS[0];
  if (isnull(id))
    return FALSE;

  # Extract ID from the path.
  id = id[0];
  if (isnull(id))
    return FALSE;

  # Check if the ID points to a used slot.
  if (isnull(_path_list[id]))
    return FALSE;

  # Delete the data structure.
  _path_list[id] = NULL;

  # Mark the slot as free.
  if (_path_freelist_pos > 0)
  {
    # Slots to the left are no longer free, so we can roll back and
    # put a new free ID in them.
    _path_freelist_pos--;
    pos = _path_freelist_pos;
  }
  else
  {
    # Slots to the right are still free, so if we're at the start of
    # the list we have to add new entries to the end.
    pos = max_index(_path_freelist);
  }

  _path_freelist[pos] = id;

  return TRUE;
}

##
# Extend a path object to point to one of its children.
#
# @anonparam path  A path object.
# @anonparam child Child indexes to add to the path.
#
# @param args A list with the path as the first element, and the child
#             indexes following.
#
# @return A path object pointing to the child specified.
##
function path_child(args)
{
  local_var i, max, maxp, path;

  # Use either named or anonymous arguments.
  if (isnull(args))
    args = _FCT_ANON_ARGS;

  path = args[0];

  max = max_index(args);
  maxp = max_index(path);
  for (i=1; i<max; i++)
  {
    # Explicitly detect NULL indexes, both to prevent errors and
    # permit the reuse of an args list.
    if (isnull(args[i]))
      break;

    path[maxp+i-1] = args[i];
  }

  return path;
}

##
# Get the object pointed to by the path.
#
# @anonparam path  A path object.
# @anonparam child Child indexes to add to the path.
#
# @param args A list with the path as the first element, and the child
#             indexes following.
#
# @return The object pointed to by the path.
##
function path_get(args)
{
  # Use either named or anonymous arguments.
  if (isnull(args))
    args = _FCT_ANON_ARGS;

  return _path_list[path_child(args:args)];
}

##
# Set the object pointed to by the path.
#
# @anonparam path  A path object.
# @anonparam child Child indexes to add to the path.
#
# @param args A list with the path as the first element, and the child
#             indexes following.
# @param val  The value to set the path to.
##
function path_set(args, val)
{
  # Use either named or anonymous arguments.
  if (isnull(args))
    args = _FCT_ANON_ARGS;

  _path_list[path_child(args:args)] = val;
}

##
# Find the number of items in a list the path points to.
#
# @anonparam path  A path object.
# @anonparam child Child indexes to add to the path.
#
# @param args A list with the path as the first element, and the child
#             indexes following.
#
# @return An integer representing the list's size.
##
function path_max(args)
{
  # Use either named or anonymous arguments.
  if (isnull(args))
    args = _FCT_ANON_ARGS;

  return max_index(path_get(args:args));
}

##
# Get the keys from the array / list the path points to.
#
# @anonparam path  A path object.
# @anonparam child Child indexes to add to the path.
#
# @param args A list with the path as the first element, and the child
#             indexes following.
#
# @return A list of keys.
##
function path_keys(args)
{
  # Use either named or anonymous arguments.
  if (isnull(args))
    args = _FCT_ANON_ARGS;

  return keys(path_get(args:args));
}

##
# Determine whether the object the path pointed to is NULL.
#
# @anonparam path  A path object.
# @anonparam child Child indexes to add to the path.
#
# @param args A list with the path as the first element, and the child
#             indexes following.
#
# @return A boolean indicating whether the object the path pointed to
#         was NULL.
##
function path_isnull(args)
{
  # Use either named or anonymous arguments.
  if (isnull(args))
    args = _FCT_ANON_ARGS;

  return isnull(path_get(args:args));
}

##
# Get the type of the object pointed to by the path.
#
# @anonparam path  A path object.
# @anonparam child Child indexes to add to the path.
#
# @param args A list with the path as the first element, and the child
#             indexes following.
#
# @return A string naming the type of object the path pointed to.
##
function path_typeof(args)
{
  # Use either named or anonymous arguments.
  if (isnull(args))
    args = _FCT_ANON_ARGS;

  return typeof(path_get(args:args));
}
