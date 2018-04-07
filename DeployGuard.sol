pragma solidity ^0.4.21;


//////////////////////////////
//                          //
//       DSAuthority        //
//                          //
//////////////////////////////

contract DSAuthority {
    function canCall(
        address src, address dst, bytes4 sig
    ) public view returns (bool);
}

contract DSAuthEvents {
    event LogSetAuthority (address indexed authority);
    event LogSetOwner     (address indexed owner);
}


//////////////////////////////
//                          //
//          DSAuth          //
//                          //
//////////////////////////////

contract DSAuth is DSAuthEvents {
    DSAuthority  public  authority;
    address      public  owner;

    function DSAuth() public {
        owner = msg.sender;
        emit LogSetOwner(msg.sender);
    }

    function setOwner(address owner_)
        public
        auth
    {
        owner = owner_;
        emit LogSetOwner(owner);
    }

    function setAuthority(DSAuthority authority_)
        public
        auth
    {
        authority = authority_;
        emit LogSetAuthority(authority);
    }

    modifier auth {
        require(isAuthorized(msg.sender, msg.sig));
        _;
    }

    function isAuthorized(address src, bytes4 sig) internal view returns (bool) {
        if (src == address(this)) {
            return true;
        } else if (src == owner) {
            return true;
        } else if (authority == DSAuthority(0)) {
            return false;
        } else {
            return authority.canCall(src, this, sig);
        }
    }
}



//////////////////////////////
//                          //
//         DSGuard          //
//                          //
//////////////////////////////

contract DSGuardEvents {
    event LogPermit(
        bytes32 indexed src,
        bytes32 indexed dst,
        bytes32 indexed sig
    );

    event LogForbid(
        bytes32 indexed src,
        bytes32 indexed dst,
        bytes32 indexed sig
    );
}

contract DSGuard is DSAuth, DSAuthority, DSGuardEvents {
    bytes32 constant public ANY = bytes32(uint(-1));

    mapping (bytes32 => mapping (bytes32 => mapping (bytes32 => bool))) acl;

    function canCall(
        address src_, address dst_, bytes4 sig
    ) public view returns (bool) {
        var src = bytes32(src_);
        var dst = bytes32(dst_);

        return acl[src][dst][sig]
            || acl[src][dst][ANY]
            || acl[src][ANY][sig]
            || acl[src][ANY][ANY]
            || acl[ANY][dst][sig]
            || acl[ANY][dst][ANY]
            || acl[ANY][ANY][sig]
            || acl[ANY][ANY][ANY];
    }

    function permit(bytes32 src, bytes32 dst, bytes32 sig) public auth {
        acl[src][dst][sig] = true;
        LogPermit(src, dst, sig);
    }

    function forbid(bytes32 src, bytes32 dst, bytes32 sig) public auth {
        acl[src][dst][sig] = false;
        LogForbid(src, dst, sig);
    }

    function permit(address src, address dst, bytes32 sig) public {
        permit(bytes32(src), bytes32(dst), sig);
    }
    function forbid(address src, address dst, bytes32 sig) public {
        forbid(bytes32(src), bytes32(dst), sig);
    }

}

contract DSGuardFactory {
    mapping (address => bool)  public  isGuard;

    function newGuard() public returns (DSGuard guard) {
        guard = new DSGuard();
        guard.setOwner(msg.sender);
        isGuard[guard] = true;
    }
}

contract ContractFactory is DSAuth {
    address[] public deployedContracts;
    DeployGuard guard;

    function ContractFactory(DeployGuard guard_) public {
        guard = guard_;
        setAuthority(guard);
        setOwner(0);
    }

    function createContract(string name, uint minimum) public {

        address newContract = new Contract(name, minimum, msg.sender);
        deployedContracts.push(newContract);
        setOwner(0);
    }

     function getDeployedContracts() public view returns (address[]) {
        return deployedContracts;
    }


    function destroy() public auth {
        selfdestruct(msg.sender);
    }

    function enable() {
        guard.permit(S("createContract(string,uint256)"));
    }

    function S(string s) internal pure returns (bytes4) {
        return bytes4(keccak256(s));
    }
}

contract Contract {
struct Request {
        string description;
        uint value;
        address recipient;
        bool complete;
        uint approvalCount;
        mapping(address => bool) approvals;
    }

    Request[] public requests;
    string public name;
    address public manager;
    uint public minimumContribution;
    mapping(address => bool) public approvers;


    modifier restricted() {
        require(msg.sender == manager);
        _;
    }

    function Contract(string contractName, uint minimum, address creator) public {
        manager = creator;
        name = contractName;
        minimumContribution = minimum;
    }
}

contract DeployGuard is DSAuthority {
    mapping(bytes4 => bool) acl;

    function permit(bytes4 sig) public {
        acl[sig] = true;
    }

    function canCall(
        address scr_, address dst_, bytes4 sig
    ) public view returns (bool) {
        return (acl[sig] && isOwner());
    }

    function isOwner() internal view returns (bool) {
        return true;
    }
}

