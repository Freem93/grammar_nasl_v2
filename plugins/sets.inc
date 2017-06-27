

namespace collib {
include("lists.inc");
######################################################################
# EVERYTHING YOU EVER WANTED TO IMPLEMENT WITH SETS, 
# BUT WERE AFRAID TO ASK
######################################################################

# a kludge for working around the awkward fact that you can't 
# call a global function from within an object if the object has
# a function of the same name. 
global_var _contains_alias = @contains;
global_var _map_alias = @map;
global_var _hashable_types = {'string':1, 'int':1, 'uint':1, 'data':1, 'boolean':1};
global_var __acc_table = {'data':'', 'int':0, 'list':make_list(), 'set':make_set() };

##
# @anonparam items to include in the resulting set as elements,
# either passed separately or in a list (the function works in a
# way similar to make_list().
# @return a set object containing the items supplied, without
# repetitions.
##
function make_set()
{
  return new ('collib::set', _FCT_ANON_ARGS);
}


# helper function for some map operations internal to the set object
function _set_to_list()
{
  return _FCT_ANON_ARGS[0].to_list();
}


##
# @remark A set is an unordered collection type without duplicate
# elements. It is implemented, here, with efficient methods for
# data insertion and retrieval (O(1)).
##
object set 
{
  var arr;

  ##
  # @anonparam items to insert into the set, passed either separately or
  # as a list
  # @return set object containing the objects passed to the constructor
  ##
  function set ()
  {
    var elem;
    this.arr = make_array();
    if (isnull(_FCT_ANON_ARGS[0]))
      return;
    foreach (elem in _FCT_ANON_ARGS)
      this.insert(elem);
  }

  ##
  # @anonparam items to insert into the set, passed either separately or
  # as a list.
  # @return NULL
  # @remark Modifies the set in place.
  ##
  public function insert ()
  {
    local_var t, elem;
    t = typeof_ex(_FCT_ANON_ARGS[0]);
    if (t == 'list')
      foreach (elem in _FCT_ANON_ARGS[0])
        this.insert(elem);
    else if (_hashable_types[t])
      this.arr[_FCT_ANON_ARGS[0]] = t;
    else exit(1, 'ERROR: unhashable type passed to set.insert(): '+t);
  }

  ##
  # @anonparam items to remove from the set (variable number thereof)
  # @return NULL
  # @remark modifies the set in-place.
  ##
  public function remove ()
  {
    var elem;
    foreach (elem in _FCT_ANON_ARGS)
    {
      if (this.contains(elem))
        this.arr[elem] = NULL;
    }
  }

  ##
  # @param f function pointer, a comparator to use in place
  # of identity
  # @param args list of additional arguments to pass to f
  # @anonparam element to search for in the set
  # @return TRUE if element is in the set, FALSE otherwise
  # @remark runs in O(1) time if no comparator function is used,
  # but O(n) otherwise.
  ##
  public function contains (f, args)
  {
    if (isnull(f))
      return !isnull(this.arr[_FCT_ANON_ARGS[0]]);
    if (!isnull(f)) 
      return contains(f:f, args:args, this.to_list(), 
                      _FCT_ANON_ARGS[0]);
  }


  ##
  # @param f The function that each item will be run through.
  # @param args Optional additional args to be added to the end of f.
  # @return The set {apply(f:f, args:args, x) | x in original list}
  # @remark
  # let S be the set containing elements 1, 2 and 3
  # example: S.map(f:plus_one)
  #          -> {plus_one(1), plus_one(2), plus_one(3)}
  #
  # example: S.map(f:plus, args:[4]);
  #          -> {plus(1,4), plus(2,4), plus(3,4)}
  ##
  public function map (f, args)
  {
    return make_set(_map_alias(f:f, args:args,
                    this.to_list()));
  }

  ##
  # @return list of elements in the set
  ##
  public function to_list ()
  {
    var k;
    var aslist = make_list();
    foreach (k in keys(this.arr))
      if (this.arr[k] == 'int')
        push (int(k), aslist);
      else if (this.arr[k])
        push (k, aslist);
    return aslist;
  }

  ##
  # @anonparam additional sets
  # @return set containing all original elements, together with elements
  # in argument set(s).
  # @remark O(n). Use sparingly.
  ##
  public function union ()
  {
    typecheck(type:'set', exit_on_fail:TRUE, caller:'set.union()', _FCT_ANON_ARGS);
    ## debug
    local_var un;
    un = make_set();
    un.insert(_map_alias(f:@_set_to_list, _FCT_ANON_ARGS));
    un.insert(this.to_list());
    return un;
  }

  ##
  # @anonparam additional sets to intersect with this set
  # @return set containing only those elements common to this
  # set and all the other sets passed as parameters
  ##
  public function intersection ()
  {
    typecheck(type:'set', exit_on_fail:TRUE, caller:'set.intersection()', _FCT_ANON_ARGS);
    var inter, elem, s;
    inter = make_set();
    foreach (elem in this.to_list())
    {
      local_var ok = TRUE;
      foreach (s in _FCT_ANON_ARGS)
        if (!s.contains(elem)) 
        {
          ok = FALSE;
          break;
        }
      if (ok) inter.insert(elem);
    }
    return inter;
  }

  ##
  # @anonparam 1st set to take difference from this from
  # @return set containing only those elements not belonging to
  # the intersection of this and 1st
  ##
  public function difference (asymmetrical)
  {
    typecheck(type:'set', exit_on_fail:TRUE, caller:'set.difference()', _FCT_ANON_ARGS);
    local_var item;
    local_var diff = new('collib::set');
    foreach (item in this.to_list())
      if (!_FCT_ANON_ARGS[0].contains(item))
        diff.insert(item);
    if (!asymmetrical) 
      foreach (item in _FCT_ANON_ARGS[0].to_list())
        if (!this.contains(item)) 
          diff.insert(item);
    return diff;
  }

  # note: it would be simpler to make subtract primitive
  # and then construct difference as the union of
  # (A-B) U (B-A), but this approach would be less
  # efficient, so I've sacrificed elegance in this case.

  ##
  # @anonparam set to subtract from this set
  # @return set containing only those elements that belong to this
  # set, but not to the set passed as parameter.
  ##
  public function subtract ()
  {
    typecheck(type:'set', exit_on_fail:TRUE, caller:'set.subtract()', _FCT_ANON_ARGS);
    return this.difference(_FCT_ANON_ARGS[0], asymmetrical:TRUE);
  }

  ##
  # @anonparam set to check for equality with this set
  # @return TRUE if both sets contain exactly the same elements, FALSE otherwise
  ##
  public function equals ()
  {
    typecheck(type:'set', exit_on_fail:TRUE, caller:'set.equals()', _FCT_ANON_ARGS);
    return this.is_subset(_FCT_ANON_ARGS[0]) && _FCT_ANON_ARGS[0].is_subset(this);
  }
  
  ##
  # @anonparam set to compare with this set
  # @return TRUE if this set is a subet of the parameter set, and FALSE otherwise
  ##
  public function is_subset ()
  {
    var elem;
    typecheck(type:'set', exit_on_fail:TRUE, caller:'set.subset()', _FCT_ANON_ARGS);
    foreach (elem in keys(this.arr))
    {
      if (!this.arr[elem]) continue;
      if (!_FCT_ANON_ARGS[0].contains(elem)) return FALSE;
    }
    return TRUE;
  }

  ##
  # @return a string representation of this set
  ##
  public function to_string ()
  {
    return '{'+ereg_replace(string:serialize(this.to_list()),
                            pattern:"[\[\]]",
                            replace:'')+'}';
  }
}


##
# @param type the type the caller is checking for
# @param exit_on_fail  boolean. TRUE will cause the function to call exit() if the
#                      values passed don't match the specified type.
# @param caller        a string providing the name of the calling function
# @anonparam           a list containing the values to be typechecked. Typically,
#                      this is going to be something like _FCT_ANON_ARGS.
# @return boolean      TRUE if the arguments pass the type check, FALSE otherwise.
# @remark              typecheck can be effectively disabled by setting the global
#                      variable _TYPECHECKER_ to FALSE. In this case, this function
#                      will always return TRUE. This can improve efficiency at the
#                      cost of runtime safety.
##
function typecheck (type, exit_on_fail, caller)
{
  if (!_TYPECHECKER_) return TRUE;
  local_var types, ret;
  if (isnull(type))
    exit(1, 'ERROR: no type parameter supplied to typecheck()');
  if (isnull(caller))
    caller = '';
  else
    caller = '\nCaller: '+caller;
  types = map(f:@typeof_ex, _FCT_ANON_ARGS[0]);
  ret = all(f:@eq, args:make_list(type), types);
  if (exit_on_fail && !ret)
    exit(1, 'ERROR: arguments failed typecheck().\nDesired type: '+ type +
        '\nActual types: '+reduce(f:@plus, map(f:@typeof_ex, _FCT_ANON_ARGS[0]))+ caller);
  return ret;
}

} # end namespace collib
