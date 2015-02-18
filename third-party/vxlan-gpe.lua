--
-- VXLAN-GPE
--
-- copy this file to ~/.wireshark/plugins/
--

do
    local protocol_vxlan_gpe = Proto("vxlan-gpe", "VXLAN-GPE");
    local vxlan_flags = ProtoField.uint8("vxlan.flags","Flags",base.HEX)
    local vxlan_flag_version = ProtoField.uint8("vxlan.flags.version","Version",
        base.DEC, nil, 0x30)
    local vxlan_flag_i = ProtoField.bool("vxlan.flags.i","I Flag",8,
                {"Valid VNI Tag present", "Valid VNI Tag NOT present"}, 0x08)
    local vxlan_flag_p = ProtoField.bool("vxlan.flags.p","P Flag",8,
                {"Next Protocol Present", "Next Protocol NOT present"}, 0x04)
    local vxlan_flag_o = ProtoField.bool("vxlan.flags.o","O Flag", 8,
        {"Valid OAM Bit present", "Valid OAM Bit NOT present"}, 0x01)
    local vxlan_reserved1 = ProtoField.uint16("vxlan.reserved1","Reserved", base.HEX)
    local vxlan_nproto = ProtoField.uint8("vxlan.nproto","Next Protocol",base.HEX)
    local vxlan_vni = ProtoField.uint24("vxlan.vni","VNI",base.HEX)
    local vxlan_reserved2 = ProtoField.uint8("vxlan.reserved2","Reserved", base.HEX)

    protocol_vxlan_gpe.fields = {vxlan_flags, vxlan_flag_version, vxlan_flag_i,
                                 vxlan_flag_p, vxlan_flag_o, vxlan_reserved1,
                                 vxlan_nproto, vxlan_vni, vxlan_reserved2}

    function protocol_vxlan_gpe.dissector(buf, pinfo, root)
        local t = root:add(protocol_vxlan_gpe, buf(0,8))
        local f = t:add(vxlan_flags, buf(0,1))

        f:add(vxlan_flag_version, buf(0,1))
        f:add(vxlan_flag_i, buf(0,1))
        f:add(vxlan_flag_p, buf(0,1))
        f:add(vxlan_flag_o, buf(0,1))
        t:add(vxlan_reserved1, buf(1,2))
        t:add(vxlan_nproto, buf(3,1))
        t:add(vxlan_vni, buf(4,3))
        t:add(vxlan_reserved2, buf(7,1))
        t:append_text(", VNI: 0x" .. string.format("%x",buf(4, 3):uint())
                      .. ", Next Protocol: 0x" .. string.format("%x",buf(3, 1):uint()))

        local eth_dis = Dissector.get("eth")
        eth_dis:call(buf(8):tvb(), pinfo, root)
    end

    local udp_encap_table = DissectorTable.get("udp.port")
    udp_encap_table:add(4790, protocol_vxlan_gpe)
end
