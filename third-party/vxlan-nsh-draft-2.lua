--
-- VXLAN and Network Service Header Dissector
-- VXLAN part borrowed from http://www.lovemytool.com/blog/2011/11/analyzing-
-- vxlan-packets-using-wireshark-by-srivats-p.html
--
-- copy this file to ~/.wireshark/plugins/
--

do
    local p_vxlan = Proto("vxlan1","Virtual eXtended LAN");

    local f_flags = ProtoField.uint8("vxlan.flags","Flags",base.HEX)
    local f_flag_i = ProtoField.bool("vxlan.flags.i","I Flag",8,
                {"Valid VNI Tag present", "Valid VNI Tag NOT present"}, 0x08)
    local f_rsvd1 = ProtoField.uint24("vxlan.rsvd1","Reserved", base.HEX)
    local f_vni = ProtoField.uint24("vxlan.vni","VNI",base.HEX)
    local f_rsvd2 = ProtoField.uint8("vxlan.rsvd2","Reserved", base.HEX)

    p_vxlan.fields = {f_flags, f_flag_i, f_rsvd1, f_vni, f_rsvd2}

    local p_nsh = Proto("nsh","Network Service Header");

    local f_nsh_flags = ProtoField.uint8("nsh.flags","Flags",base.HEX)
    local f_nsh_flag_o = ProtoField.bool("nsh.flags.o","O Flag",8,
        {"Valid OAM Bit present", "Valid OAM Bit NOT present"}, 0x80)
    local f_nsh_flag_c = ProtoField.bool("nsh.flags.c","C Flag",8,
        {"Valid Context Bit present", "Valid Context Bit NOT present"}, 0x40)
    local f_nsh_proto_type = ProtoField.uint16("nsh.proto_type",
        "Protocol Type",base.HEX)
    local f_nsh_svc_idx = ProtoField.uint8("nsh.svc_idx","Service Index",
        base.HEX)
    local f_nsh_svc_path = ProtoField.uint24("nsh.svc_path","Service Path",
        base.HEX)
    local f_nsh_rsvd3 = ProtoField.uint8("nsh.rsvd3","Reserved",base.HEX)
    local f_nsh_net_plt_ctx = ProtoField.uint32("nsh.net_plt_ctx",
        "Network Platform Context",base.HEX)
    local f_nsh_net_shd_ctx = ProtoField.uint32("nsh.net_shd_ctx",
        "Network Shared Context",base.HEX)
    local f_nsh_svc_plt_ctx = ProtoField.uint32("nsh.svc_plt_ctx",
        "Service Paltform Context",base.HEX)
    local f_nsh_svc_shd_ctx = ProtoField.uint32("nsh.svc_shd_ctx",
        "Service Shared Context",base.HEX)

    p_nsh.fields = {f_nsh_flags, f_nsh_flag_o, f_nsh_flag_c, f_nsh_proto_type,
        f_nsh_svc_idx, f_nsh_svc_path, f_nsh_rsvd3, f_nsh_net_plt_ctx,
        f_nsh_net_shd_ctx, f_nsh_svc_plt_ctx, f_nsh_svc_shd_ctx}

    function p_vxlan.dissector(buf, pinfo, root)
        local t = root:add(p_vxlan, buf(0,8))

        local f = t:add(f_flags, buf(0,1))
        f:add(f_flag_i, buf(0,1))

        t:add(f_rsvd1, buf(1,3))
        t:add(f_vni, buf(4,3))
        t:add(f_rsvd2, buf(7,1))

        t:append_text(", VNI: 0x" .. string.format("%x",
            buf(4, 3):uint()))

        local eth_dis = Dissector.get("eth")
        eth_dis:call(buf(8):tvb(), pinfo, root)
    end

    function p_nsh.dissector(buf, pinfo, root)
        local t = root:add(p_vxlan, buf(0,8))

        local f = t:add(f_flags, buf(0,1))
        f:add(f_flag_i, buf(0,1))

        t:add(f_rsvd1, buf(1,3))
        t:add(f_vni, buf(4,3))
        t:add(f_rsvd2, buf(7,1))

        t:append_text(", VNI: 0x" .. string.format("%x",
            buf(4, 3):uint()))

        local nsh_t = root:add(p_nsh, buf(8,24))
       
        local nsh_f = nsh_t:add(f_nsh_flags, buf(8,1))
        nsh_f:add(f_nsh_flag_o, buf(8,1))
        nsh_f:add(f_nsh_flag_c, buf(8,1))
       
        nsh_t:add(f_nsh_rsvd3, buf(9,1))
        nsh_t:add(f_nsh_proto_type, buf(10,2))
        nsh_t:add(f_nsh_svc_path, buf(12,3))
        nsh_t:add(f_nsh_svc_idx, buf(15,1))

        nsh_t:add(f_nsh_net_plt_ctx, buf(16,4))
        nsh_t:add(f_nsh_net_shd_ctx, buf(20,4))
        nsh_t:add(f_nsh_svc_plt_ctx, buf(24,4))
        nsh_t:add(f_nsh_svc_shd_ctx, buf(28,4))

        nsh_t:append_text(", PROTO: 0x" .. string.format("%x",
            buf(10, 2):uint()))
        nsh_t:append_text(", SVC PATH: 0x" .. string.format("%x",
            buf(12, 3):uint()))
        nsh_t:append_text(", SVC IDX: 0x" .. string.format("%x",
            buf(15, 1):uint()))

        local eth_dis = Dissector.get("eth")
        eth_dis:call(buf(32):tvb(), pinfo, root)
    end

    local udp_encap_table = DissectorTable.get("udp.port")
    udp_encap_table:add(4789, p_vxlan)
    udp_encap_table:add(6633, p_nsh)
end
