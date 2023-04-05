static void *alloc_buffer_data(struct dm_bufio_client *c, gfp_t gfp_mask,
			       unsigned char *data_mode)
{
	if (unlikely(c->slab_cache != NULL)) {
		*data_mode = DATA_MODE_SLAB;
		return kmem_cache_alloc(c->slab_cache, gfp_mask);
	}

	if (c->block_size <= KMALLOC_MAX_SIZE &&
	    gfp_mask & __GFP_NORETRY) {
		*data_mode = DATA_MODE_GET_FREE_PAGES;
		return (void *)__get_free_pages(gfp_mask,
						c->sectors_per_block_bits - (PAGE_SHIFT - SECTOR_SHIFT));
	}

	*data_mode = DATA_MODE_VMALLOC;

	if (gfp_mask & __GFP_NORETRY) {
		unsigned noio_flag = memalloc_noio_save();
		void *ptr = __vmalloc(c->block_size, gfp_mask);

		memalloc_noio_restore(noio_flag);
		return ptr;
	}

	return __vmalloc(c->block_size, gfp_mask);
}
////
struct nfc_llc *nfc_llc_allocate(const char *name, struct nfc_hci_dev *hdev,
				 xmit_to_drv_t xmit_to_drv,
				 rcv_to_hci_t rcv_to_hci, int tx_headroom,
				 int tx_tailroom, llc_failure_t llc_failure)
{
	struct nfc_llc_engine *llc_engine;
	struct nfc_llc *llc;

	llc_engine = nfc_llc_name_to_engine(name);
	if (llc_engine == NULL)
		return NULL;

	llc = kzalloc(sizeof(struct nfc_llc), GFP_KERNEL);
	if (llc == NULL)
		return NULL;

	llc->data = llc_engine->ops->init(hdev, xmit_to_drv, rcv_to_hci,
					  tx_headroom, tx_tailroom,
					  &llc->rx_headroom, &llc->rx_tailroom,
					  llc_failure);
	if (llc->data == NULL) {
		kfree(llc);
		return NULL;
	}
	llc->ops = llc_engine->ops;

	return llc;
}
////
static struct sk_buff *
ath10k_wmi_tlv_op_gen_beacon_dma(struct ath10k *ar, u32 vdev_id,
				 const void *bcn, size_t bcn_len,
				 u32 bcn_paddr, bool dtim_zero,
				 bool deliver_cab)

{
	struct wmi_bcn_tx_ref_cmd *cmd;
	struct wmi_tlv *tlv;
	struct sk_buff *skb;
	struct ieee80211_hdr *hdr;
	u16 fc;

	skb = ath10k_wmi_alloc_skb(ar, sizeof(*tlv) + sizeof(*cmd));
	if (!skb)
		return ERR_PTR(-ENOMEM);

	hdr = (struct ieee80211_hdr *)bcn;
	fc = le16_to_cpu(hdr->frame_control);

	tlv = (void *)skb->data;
	tlv->tag = __cpu_to_le16(WMI_TLV_TAG_STRUCT_BCN_SEND_FROM_HOST_CMD);
	tlv->len = __cpu_to_le16(sizeof(*cmd));
	cmd = (void *)tlv->value;
	cmd->vdev_id = __cpu_to_le32(vdev_id);
	cmd->data_len = __cpu_to_le32(bcn_len);
	cmd->data_ptr = __cpu_to_le32(bcn_paddr);
	cmd->msdu_id = 0;
	cmd->frame_control = __cpu_to_le32(fc);
	cmd->flags = 0;

	if (dtim_zero)
		cmd->flags |= __cpu_to_le32(WMI_BCN_TX_REF_FLAG_DTIM_ZERO);

	if (deliver_cab)
		cmd->flags |= __cpu_to_le32(WMI_BCN_TX_REF_FLAG_DELIVER_CAB);

	ath10k_dbg(ar, ATH10K_DBG_WMI, "wmi tlv beacon dma\n");
	return skb;
}
////
static struct sk_buff *
ath10k_wmi_tlv_op_gen_vdev_up(struct ath10k *ar, u32 vdev_id, u32 aid,
			      const u8 *bssid)

{
	struct wmi_vdev_up_cmd *cmd;
	struct wmi_tlv *tlv;
	struct sk_buff *skb;

	skb = ath10k_wmi_alloc_skb(ar, sizeof(*tlv) + sizeof(*cmd));
	if (!skb)
		return ERR_PTR(-ENOMEM);

	tlv = (void *)skb->data;
	tlv->tag = __cpu_to_le16(WMI_TLV_TAG_STRUCT_VDEV_UP_CMD);
	tlv->len = __cpu_to_le16(sizeof(*cmd));
	cmd = (void *)tlv->value;
	cmd->vdev_id = __cpu_to_le32(vdev_id);
	cmd->vdev_assoc_id = __cpu_to_le32(aid);
	ether_addr_copy(cmd->vdev_bssid.addr, bssid);

	ath10k_dbg(ar, ATH10K_DBG_WMI, "wmi tlv vdev up\n");
	return skb;
}
////
static struct audit_buffer *audit_buffer_alloc(struct audit_context *ctx,
					       gfp_t gfp_mask, int type)
{
	struct audit_buffer *ab;

	ab = kmem_cache_alloc(audit_buffer_cache, gfp_mask);
	if (!ab)
		return NULL;

	ab->skb = nlmsg_new(AUDIT_BUFSIZ, gfp_mask);
	if (!ab->skb)
		goto err;
	if (!nlmsg_put(ab->skb, 0, 0, type, 0, 0))
		goto err;

	ab->ctx = ctx;
	ab->gfp_mask = gfp_mask;

	return ab;

err:
	audit_buffer_free(ab);
	return NULL;
}
////
struct msr *msrs_alloc(void)
{
	struct msr *msrs = NULL;

	msrs = alloc_percpu(struct msr);
	if (!msrs) {
		pr_warn("%s: error allocating msrs\n", __func__);
		return NULL;
	}

	return msrs;
}
////
static void
xfs_iext_realloc_root(
	struct xfs_ifork	*ifp,
	struct xfs_iext_cursor	*cur)
{
	int64_t new_size = ifp->if_bytes + sizeof(struct xfs_iext_rec);
	void *new;

	/* account for the prev/next pointers */
	if (new_size / sizeof(struct xfs_iext_rec) == RECS_PER_LEAF)
		new_size = NODE_SIZE;

	new = krealloc(ifp->if_u1.if_root, new_size, GFP_NOFS | __GFP_NOFAIL);
	memset(new + ifp->if_bytes, 0, new_size - ifp->if_bytes);
	ifp->if_u1.if_root = new;
	cur->leaf = new;
}
////
static u32 *iopte_alloc(struct omap_iommu *obj, u32 *iopgd,
			dma_addr_t *pt_dma, u32 da)
{
	u32 *iopte;
	unsigned long offset = iopgd_index(da) * sizeof(da);

	/* a table has already existed */
	if (*iopgd)
		goto pte_ready;

	/*
	 * do the allocation outside the page table lock
	 */
	spin_unlock(&obj->page_table_lock);
	iopte = kmem_cache_zalloc(iopte_cachep, GFP_KERNEL);
	spin_lock(&obj->page_table_lock);

	if (!*iopgd) {
		if (!iopte)
			return ERR_PTR(-ENOMEM);

		*pt_dma = dma_map_single(obj->dev, iopte, IOPTE_TABLE_SIZE,
					 DMA_TO_DEVICE);
		if (dma_mapping_error(obj->dev, *pt_dma)) {
			dev_err(obj->dev, "DMA map error for L2 table\n");
			iopte_free(obj, iopte, false);
			return ERR_PTR(-ENOMEM);
		}

		/*
		 * we rely on dma address and the physical address to be
		 * the same for mapping the L2 table
		 */
		if (WARN_ON(*pt_dma != virt_to_phys(iopte))) {
			dev_err(obj->dev, "DMA translation error for L2 table\n");
			dma_unmap_single(obj->dev, *pt_dma, IOPTE_TABLE_SIZE,
					 DMA_TO_DEVICE);
			iopte_free(obj, iopte, false);
			return ERR_PTR(-ENOMEM);
		}

		*iopgd = virt_to_phys(iopte) | IOPGD_TABLE;

		flush_iopte_range(obj->dev, obj->pd_dma, offset, 1);
		dev_vdbg(obj->dev, "%s: a new pte:%p\n", __func__, iopte);
	} else {
		/* We raced, free the reduniovant table */
		iopte_free(obj, iopte, false);
	}

pte_ready:
	iopte = iopte_offset(iopgd, da);
	*pt_dma = iopgd_page_paddr(iopgd);
	dev_vdbg(obj->dev,
		 "%s: da:%08x pgd:%p *pgd:%08x pte:%p *pte:%08x\n",
		 __func__, da, iopgd, *iopgd, iopte, *iopte);

	return iopte;
}
////
static struct synaptics_i2c *synaptics_i2c_touch_create(struct i2c_client *client)
{
	struct synaptics_i2c *touch;

	touch = kzalloc(sizeof(struct synaptics_i2c), GFP_KERNEL);
	if (!touch)
		return NULL;

	touch->client = client;
	touch->no_decel_param = no_decel;
	touch->scan_rate_param = scan_rate;
	set_scan_rate(touch, scan_rate);
	INIT_DELAYED_WORK(&touch->dwork, synaptics_i2c_work_handler);

	return touch;
}
////
static struct intel_excl_cntrs *allocate_excl_cntrs(int cpu)
{
	struct intel_excl_cntrs *c;

	c = kzalloc_node(sizeof(struct intel_excl_cntrs),
			 GFP_KERNEL, cpu_to_node(cpu));
	if (c) {
		raw_spin_lock_init(&c->lock);
		c->core_id = -1;
	}
	return c;
}
////
struct drm_encoder *tidss_encoder_create(struct tidss_device *tidss,
					 u32 encoder_type, u32 possible_crtcs)
{
	struct drm_encoder *enc;
	int ret;

	enc = kzalloc(sizeof(*enc), GFP_KERNEL);
	if (!enc)
		return ERR_PTR(-ENOMEM);

	enc->possible_crtcs = possible_crtcs;

	ret = drm_encoder_init(&tidss->ddev, enc, &encoder_funcs,
			       encoder_type, NULL);
	if (ret < 0) {
		kfree(enc);
		return ERR_PTR(ret);
	}

	drm_encoder_helper_add(enc, &encoder_helper_funcs);

	dev_dbg(tidss->dev, "Encoder create done\n");

	return enc;
}
////
static int kvm_alloc_memslot_metadata(struct kvm *kvm,
				      struct kvm_memory_slot *slot)
{
	unsigned long npages = slot->npages;
	int i, r;

	/*
	 * Clear out the previous array pointers for the KVM_MR_MOVE case.  The
	 * old arrays will be freed by __kvm_set_memory_region() if installing
	 * the new memslot is successful.
	 */
	memset(&slot->arch, 0, sizeof(slot->arch));

	if (kvm_memslots_have_rmaps(kvm)) {
		r = memslot_rmap_alloc(slot, npages);
		if (r)
			return r;
	}

	for (i = 1; i < KVM_NR_PAGE_SIZES; ++i) {
		struct kvm_lpage_info *linfo;
		unsigned long ugfn;
		int lpages;
		int level = i + 1;

		lpages = __kvm_mmu_slot_lpages(slot, npages, level);

		linfo = __vcalloc(lpages, sizeof(*linfo), GFP_KERNEL_ACCOUNT);
		if (!linfo)
			goto out_free;

		slot->arch.lpage_info[i - 1] = linfo;

		if (slot->base_gfn & (KVM_PAGES_PER_HPAGE(level) - 1))
			linfo[0].disallow_lpage = 1;
		if ((slot->base_gfn + npages) & (KVM_PAGES_PER_HPAGE(level) - 1))
			linfo[lpages - 1].disallow_lpage = 1;
		ugfn = slot->userspace_addr >> PAGE_SHIFT;
		/*
		 * If the gfn and userspace address are not aligned wrt each
		 * other, disable large page support for this slot.
		 */
		if ((slot->base_gfn ^ ugfn) & (KVM_PAGES_PER_HPAGE(level) - 1)) {
			unsigned long j;

			for (j = 0; j < lpages; ++j)
				linfo[j].disallow_lpage = 1;
		}
	}

	if (kvm_page_track_create_memslot(kvm, slot, npages))
		goto out_free;

	return 0;

out_free:
	memslot_rmap_free(slot);

	for (i = 1; i < KVM_NR_PAGE_SIZES; ++i) {
		kvfree(slot->arch.lpage_info[i - 1]);
		slot->arch.lpage_info[i - 1] = NULL;
	}
	return -ENOMEM;
}
////
static struct k3_dma_desc_sw *k3_dma_alloc_desc_resource(int num,
							struct dma_chan *chan)
{
	struct k3_dma_chan *c = to_k3_chan(chan);
	struct k3_dma_desc_sw *ds;
	struct k3_dma_dev *d = to_k3_dma(chan->device);
	int lli_limit = LLI_BLOCK_SIZE / sizeof(struct k3_desc_hw);

	if (num > lli_limit) {
		dev_dbg(chan->device->dev, "vch %p: sg num %d exceed max %d\n",
			&c->vc, num, lli_limit);
		return NULL;
	}

	ds = kzalloc(sizeof(*ds), GFP_NOWAIT);
	if (!ds)
		return NULL;

	ds->desc_hw = dma_pool_zalloc(d->pool, GFP_NOWAIT, &ds->desc_hw_lli);
	if (!ds->desc_hw) {
		dev_dbg(chan->device->dev, "vch %p: dma alloc fail\n", &c->vc);
		kfree(ds);
		return NULL;
	}
	ds->desc_num = num;
	return ds;
}
////
static int apparmor_sk_alloc_security(struct sock *sk, int family, gfp_t flags)
{
	struct aa_sk_ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), flags);
	if (!ctx)
		return -ENOMEM;

	SK_CTX(sk) = ctx;

	return 0;
}
////
struct sk_buff *sock_omalloc(struct sock *sk, unsigned long size,
			     gfp_t priority)
{
	struct sk_buff *skb;

	if (atomic_read(&sk->sk_omem_alloc) + SKB_TRUESIZE(size) >
	    READ_ONCE(sysctl_optmem_max))
		return NULL;

	skb = alloc_skb(size, priority);
	if (!skb)
		return NULL;

	atomic_add(skb->truesize, &sk->sk_omem_alloc);
	skb->sk = sk;
	skb->destructor = sock_ofree;
	return skb;
}
////
static struct sk_buff *
ath10k_wmi_tlv_op_gen_vdev_delete(struct ath10k *ar, u32 vdev_id)
{
	struct wmi_vdev_delete_cmd *cmd;
	struct wmi_tlv *tlv;
	struct sk_buff *skb;

	skb = ath10k_wmi_alloc_skb(ar, sizeof(*tlv) + sizeof(*cmd));
	if (!skb)
		return ERR_PTR(-ENOMEM);

	tlv = (void *)skb->data;
	tlv->tag = __cpu_to_le16(WMI_TLV_TAG_STRUCT_VDEV_DELETE_CMD);
	tlv->len = __cpu_to_le16(sizeof(*cmd));
	cmd = (void *)tlv->value;
	cmd->vdev_id = __cpu_to_le32(vdev_id);

	ath10k_dbg(ar, ATH10K_DBG_WMI, "wmi tlv vdev delete\n");
	return skb;
}
////
int amdgpu_amdkfd_gpuvm_import_dmabuf(struct amdgpu_device *adev,
				      struct dma_buf *dma_buf,
				      uint64_t va, void *drm_priv,
				      struct kgd_mem **mem, uint64_t *size,
				      uint64_t *mmap_offset)
{
	struct amdgpu_vm *avm = drm_priv_to_vm(drm_priv);
	struct drm_gem_object *obj;
	struct amdgpu_bo *bo;
	int ret;

	if (dma_buf->ops != &amdgpu_dmabuf_ops)
		return -EINVAL;

	obj = dma_buf->priv;
	if (drm_to_adev(obj->dev) != adev)
		return -EINVAL;

	bo = gem_to_amdgpu_bo(obj);
	if (!(bo->preferred_domains & (AMDGPU_GEM_DOMAIN_VRAM |
				    AMDGPU_GEM_DOMAIN_GTT)))
		return -EINVAL;

	*mem = kzalloc(sizeof(struct kgd_mem), GFP_KERNEL);
	if (!*mem)
		return -ENOMEM;

	ret = drm_vma_node_allow(&obj->vma_node, drm_priv);
	if (ret) {
		kfree(*mem);
		return ret;
	}

	if (size)
		*size = amdgpu_bo_size(bo);

	if (mmap_offset)
		*mmap_offset = amdgpu_bo_mmap_offset(bo);

	INIT_LIST_HEAD(&(*mem)->attachments);
	mutex_init(&(*mem)->lock);

	(*mem)->alloc_flags =
		((bo->preferred_domains & AMDGPU_GEM_DOMAIN_VRAM) ?
		KFD_IOC_ALLOC_MEM_FLAGS_VRAM : KFD_IOC_ALLOC_MEM_FLAGS_GTT)
		| KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE
		| KFD_IOC_ALLOC_MEM_FLAGS_EXECUTABLE;

	drm_gem_object_get(&bo->tbo.base);
	(*mem)->bo = bo;
	(*mem)->va = va;
	(*mem)->domain = (bo->preferred_domains & AMDGPU_GEM_DOMAIN_VRAM) ?
		AMDGPU_GEM_DOMAIN_VRAM : AMDGPU_GEM_DOMAIN_GTT;
	(*mem)->mapped_to_gpu_memory = 0;
	(*mem)->process_info = avm->process_info;
	add_kgd_mem_to_kfd_bo_list(*mem, avm->process_info, false);
	amdgpu_sync_create(&(*mem)->sync);
	(*mem)->is_imported = true;

	return 0;
}
////
struct power_supply *__must_check
devm_power_supply_register(struct device *parent,
		const struct power_supply_desc *desc,
		const struct power_supply_config *cfg)
{
	struct power_supply **ptr, *psy;

	ptr = devres_alloc(devm_power_supply_release, sizeof(*ptr), GFP_KERNEL);

	if (!ptr)
		return ERR_PTR(-ENOMEM);
	psy = __power_supply_register(parent, desc, cfg, true);
	if (IS_ERR(psy)) {
		devres_free(ptr);
	} else {
		*ptr = psy;
		devres_add(parent, ptr);
	}
	return psy;
}
////
INDIRECT_CALLABLE_SCOPE struct rt6_info *ip6_pol_route_output(struct net *net,
					     struct fib6_table *table,
					     struct flowi6 *fl6,
					     const struct sk_buff *skb,
					     int flags)
{
	return ip6_pol_route(net, table, fl6->flowi6_oif, fl6, skb, flags);
}
////
static int bnxt_alloc_ntp_fltrs(struct bnxt *bp)
{
#ifdef CONFIG_RFS_ACCEL
	int i, rc = 0;

	if (!(bp->flags & BNXT_FLAG_RFS))
		return 0;

	for (i = 0; i < BNXT_NTP_FLTR_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&bp->ntp_fltr_hash_tbl[i]);

	bp->ntp_fltr_count = 0;
	bp->ntp_fltr_bmap = bitmap_zalloc(BNXT_NTP_FLTR_MAX_FLTR, GFP_KERNEL);

	if (!bp->ntp_fltr_bmap)
		rc = -ENOMEM;

	return rc;
#else
	return 0;
#endif
}
////
struct spi_device *spi_new_device(struct spi_controller *ctlr,
				  struct spi_board_info *chip)
{
	struct spi_device	*proxy;
	int			status;

	proxy = spi_alloc_device(ctlr);
	if (!proxy)
		return NULL;

	WARN_ON(strlen(chip->modalias) >= sizeof(proxy->modalias));

	proxy->chip_select = chip->chip_select;
	proxy->max_speed_hz = chip->max_speed_hz;
	proxy->mode = chip->mode;
	proxy->irq = chip->irq;
	strscpy(proxy->modalias, chip->modalias, sizeof(proxy->modalias));
	proxy->dev.platform_data = (void *) chip->platform_data;
	proxy->controller_data = chip->controller_data;
	proxy->controller_state = NULL;

	if (chip->swnode) {
		status = device_add_software_node(&proxy->dev, chip->swnode);
		if (status) {
			dev_err(&ctlr->dev, "failed to add software node to '%s': %d\n",
				chip->modalias, status);
			goto err_dev_put;
		}
	}

	status = spi_add_device(proxy);
	if (status < 0)
		goto err_dev_put;

	return proxy;

err_dev_put:
	device_remove_software_node(&proxy->dev);
	spi_dev_put(proxy);
	return NULL;
}
////
static struct vxlan_sock *vxlan_socket_create(struct net *net, bool ipv6,
					      __be16 port, u32 flags,
					      int ifindex)
{
	struct vxlan_net *vn = net_generic(net, vxlan_net_id);
	struct vxlan_sock *vs;
	struct socket *sock;
	unsigned int h;
	struct udp_tunnel_sock_cfg tunnel_cfg;

	vs = kzalloc(sizeof(*vs), GFP_KERNEL);
	if (!vs)
		return ERR_PTR(-ENOMEM);

	for (h = 0; h < VNI_HASH_SIZE; ++h)
		INIT_HLIST_HEAD(&vs->vni_list[h]);

	sock = vxlan_create_sock(net, ipv6, port, flags, ifindex);
	if (IS_ERR(sock)) {
		kfree(vs);
		return ERR_CAST(sock);
	}

	vs->sock = sock;
	refcount_set(&vs->refcnt, 1);
	vs->flags = (flags & VXLAN_F_RCV_FLAGS);

	spin_lock(&vn->sock_lock);
	hlist_add_head_rcu(&vs->hlist, vs_head(net, port));
	udp_tunnel_notify_add_rx_port(sock,
				      (vs->flags & VXLAN_F_GPE) ?
				      UDP_TUNNEL_TYPE_VXLAN_GPE :
				      UDP_TUNNEL_TYPE_VXLAN);
	spin_unlock(&vn->sock_lock);

	memset(&tunnel_cfg, 0, sizeof(tunnel_cfg));
	tunnel_cfg.sk_user_data = vs;
	tunnel_cfg.encap_type = 1;
	tunnel_cfg.encap_rcv = vxlan_rcv;
	tunnel_cfg.encap_err_lookup = vxlan_err_lookup;
	tunnel_cfg.encap_destroy = NULL;
	tunnel_cfg.gro_receive = vxlan_gro_receive;
	tunnel_cfg.gro_complete = vxlan_gro_complete;

	setup_udp_tunnel_sock(net, sock, &tunnel_cfg);

	return vs;
}
////
int mlx4_buf_alloc(struct mlx4_dev *dev, int size, int max_direct,
		   struct mlx4_buf *buf)
{
	if (size <= max_direct) {
		return mlx4_buf_direct_alloc(dev, size, buf);
	} else {
		dma_addr_t t;
		int i;

		buf->direct.buf = NULL;
		buf->nbufs      = DIV_ROUND_UP(size, PAGE_SIZE);
		buf->npages	= buf->nbufs;
		buf->page_shift  = PAGE_SHIFT;
		buf->page_list   = kcalloc(buf->nbufs, sizeof(*buf->page_list),
					   GFP_KERNEL);
		if (!buf->page_list)
			return -ENOMEM;

		for (i = 0; i < buf->nbufs; ++i) {
			buf->page_list[i].buf =
				dma_alloc_coherent(&dev->persist->pdev->dev,
						   PAGE_SIZE, &t, GFP_KERNEL);
			if (!buf->page_list[i].buf)
				goto err_free;

			buf->page_list[i].map = t;
		}
	}

	return 0;

err_free:
	mlx4_buf_free(dev, size, buf);

	return -ENOMEM;
}
////
static struct udp_tunnel_nic *
udp_tunnel_nic_alloc(const struct udp_tunnel_nic_info *info,
		     unsigned int n_tables)
{
	struct udp_tunnel_nic *utn;
	unsigned int i;

	utn = kzalloc(sizeof(*utn), GFP_KERNEL);
	if (!utn)
		return NULL;
	utn->n_tables = n_tables;
	INIT_WORK(&utn->work, udp_tunnel_nic_device_sync_work);

	utn->entries = kmalloc_array(n_tables, sizeof(void *), GFP_KERNEL);
	if (!utn->entries)
		goto err_free_utn;

	for (i = 0; i < n_tables; i++) {
		utn->entries[i] = kcalloc(info->tables[i].n_entries,
					  sizeof(*utn->entries[i]), GFP_KERNEL);
		if (!utn->entries[i])
			goto err_free_prev_entries;
	}

	return utn;

err_free_prev_entries:
	while (i--)
		kfree(utn->entries[i]);
	kfree(utn->entries);
err_free_utn:
	kfree(utn);
	return NULL;
}
////
struct rxrpc_connection *rxrpc_prealloc_service_connection(struct rxrpc_net *rxnet,
							   gfp_t gfp)
{
	struct rxrpc_connection *conn = rxrpc_alloc_connection(rxnet, gfp);

	if (conn) {
		conn->state = RXRPC_CONN_SERVICE_PREALLOC;
		refcount_set(&conn->ref, 2);
		conn->bundle = rxrpc_get_bundle(&rxrpc_service_dummy_bundle,
						rxrpc_bundle_get_service_conn);

		atomic_inc(&rxnet->nr_conns);
		write_lock(&rxnet->conn_lock);
		list_add_tail(&conn->link, &rxnet->service_conns);
		list_add_tail(&conn->proc_link, &rxnet->conn_proc_list);
		write_unlock(&rxnet->conn_lock);

		rxrpc_see_connection(conn, rxrpc_conn_new_service);
	}

	return conn;
}
////
static struct mask_array *tbl_mask_array_alloc(int size)
{
	struct mask_array *new;

	size = max(MASK_ARRAY_SIZE_MIN, size);
	new = kzalloc(sizeof(struct mask_array) +
		      sizeof(struct sw_flow_mask *) * size +
		      sizeof(u64) * size, GFP_KERNEL);
	if (!new)
		return NULL;

	new->masks_usage_zero_cntr = (u64 *)((u8 *)new +
					     sizeof(struct mask_array) +
					     sizeof(struct sw_flow_mask *) *
					     size);

	new->masks_usage_stats = __alloc_percpu(sizeof(struct mask_array_stats) +
						sizeof(u64) * size,
						__alignof__(u64));
	if (!new->masks_usage_stats) {
		kfree(new);
		return NULL;
	}

	new->count = 0;
	new->max = size;

	return new;
}
////
static struct mlx5_fpga_device *mlx5_fpga_device_alloc(void)
{
	struct mlx5_fpga_device *fdev = NULL;

	fdev = kzalloc(sizeof(*fdev), GFP_KERNEL);
	if (!fdev)
		return NULL;

	spin_lock_init(&fdev->state_lock);
	fdev->state = MLX5_FPGA_STATUS_NONE;
	return fdev;
}
////
static int
nfp_abm_vnic_alloc(struct nfp_app *app, struct nfp_net *nn, unsigned int id)
{
	struct nfp_eth_table_port *eth_port = &app->pf->eth_tbl->ports[id];
	struct nfp_abm *abm = app->priv;
	struct nfp_abm_link *alink;
	int err;

	alink = kzalloc(sizeof(*alink), GFP_KERNEL);
	if (!alink)
		return -ENOMEM;
	nn->app_priv = alink;
	alink->abm = abm;
	alink->vnic = nn;
	alink->id = id;
	alink->total_queues = alink->vnic->max_rx_rings;

	INIT_LIST_HEAD(&alink->dscp_map);

	err = nfp_abm_ctrl_read_params(alink);
	if (err)
		goto err_free_alink;

	alink->prio_map = kzalloc(abm->prio_map_len, GFP_KERNEL);
	if (!alink->prio_map) {
		err = -ENOMEM;
		goto err_free_alink;
	}

	err = nfp_eth_set_configured(app->cpp, eth_port->index, true);
	if (err < 0)
		goto err_free_priomap;

	netif_keep_dst(nn->dp.netdev);

	nfp_abm_vnic_set_mac(app->pf, abm, nn, id);
	INIT_RADIX_TREE(&alink->qdiscs, GFP_KERNEL);

	return 0;

err_free_priomap:
	kfree(alink->prio_map);
err_free_alink:
	kfree(alink);
	return err;
}
////
static int at91ether_clk_init(struct platform_device *pdev, struct clk **pclk,
			      struct clk **hclk, struct clk **tx_clk,
			      struct clk **rx_clk, struct clk **tsu_clk)
{
	int err;

	*hclk = NULL;
	*tx_clk = NULL;
	*rx_clk = NULL;
	*tsu_clk = NULL;

	*pclk = devm_clk_get(&pdev->dev, "ether_clk");
	if (IS_ERR(*pclk))
		return PTR_ERR(*pclk);

	err = clk_prepare_enable(*pclk);
	if (err) {
		dev_err(&pdev->dev, "failed to enable pclk (%d)\n", err);
		return err;
	}

	return 0;
}
////
int pn532_i2c_nfc_alloc(struct pn533 *priv, u32 protocols,
			struct device *parent)
{
	priv->nfc_dev = nfc_allocate_device(&pn533_nfc_ops, protocols,
					   priv->ops->tx_header_len +
					   PN533_CMD_DATAEXCH_HEAD_LEN,
					   priv->ops->tx_tail_len);
	if (!priv->nfc_dev)
		return -ENOMEM;

	nfc_set_parent_dev(priv->nfc_dev, parent);
	nfc_set_drvdata(priv->nfc_dev, priv);
	return 0;
}
////
static unsigned int *copy_tlv(const unsigned int __user *_tlv, bool in_kernel)
{
	unsigned int data[2];
	unsigned int *tlv;

	if (!_tlv)
		return NULL;
	if (in_kernel)
		memcpy(data, (__force void *)_tlv, sizeof(data));
	else if (copy_from_user(data, _tlv, sizeof(data)))
		return NULL;
	if (data[1] >= MAX_TLV_SIZE)
		return NULL;
	tlv = kmalloc(data[1] + sizeof(data), GFP_KERNEL);
	if (!tlv)
		return NULL;
	memcpy(tlv, data, sizeof(data));
	if (in_kernel) {
		memcpy(tlv + 2, (__force void *)(_tlv + 2),  data[1]);
	} else if (copy_from_user(tlv + 2, _tlv + 2, data[1])) {
		kfree(tlv);
		return NULL;
	}
	return tlv;
}
////
static struct ring_buffer_per_cpu *
rb_allocate_cpu_buffer(struct trace_buffer *buffer, long nr_pages, int cpu)
{
	struct ring_buffer_per_cpu *cpu_buffer;
	struct buffer_page *bpage;
	struct page *page;
	int ret;

	cpu_buffer = kzalloc_node(ALIGN(sizeof(*cpu_buffer), cache_line_size()),
				  GFP_KERNEL, cpu_to_node(cpu));
	if (!cpu_buffer)
		return NULL;

	cpu_buffer->cpu = cpu;
	cpu_buffer->buffer = buffer;
	raw_spin_lock_init(&cpu_buffer->reader_lock);
	lockdep_set_class(&cpu_buffer->reader_lock, buffer->reader_lock_key);
	cpu_buffer->lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
	INIT_WORK(&cpu_buffer->update_pages_work, update_pages_handler);
	init_completion(&cpu_buffer->update_done);
	init_irq_work(&cpu_buffer->irq_work.work, rb_wake_up_waiters);
	init_waitqueue_head(&cpu_buffer->irq_work.waiters);
	init_waitqueue_head(&cpu_buffer->irq_work.full_waiters);

	bpage = kzalloc_node(ALIGN(sizeof(*bpage), cache_line_size()),
			    GFP_KERNEL, cpu_to_node(cpu));
	if (!bpage)
		goto fail_free_buffer;

	rb_check_bpage(cpu_buffer, bpage);

	cpu_buffer->reader_page = bpage;
	page = alloc_pages_node(cpu_to_node(cpu), GFP_KERNEL, 0);
	if (!page)
		goto fail_free_reader;
	bpage->page = page_address(page);
	rb_init_page(bpage->page);

	INIT_LIST_HEAD(&cpu_buffer->reader_page->list);
	INIT_LIST_HEAD(&cpu_buffer->new_pages);

	ret = rb_allocate_pages(cpu_buffer, nr_pages);
	if (ret < 0)
		goto fail_free_reader;

	cpu_buffer->head_page
		= list_entry(cpu_buffer->pages, struct buffer_page, list);
	cpu_buffer->tail_page = cpu_buffer->commit_page = cpu_buffer->head_page;

	rb_head_page_activate(cpu_buffer);

	return cpu_buffer;

 fail_free_reader:
	free_buffer_page(cpu_buffer->reader_page);

 fail_free_buffer:
	kfree(cpu_buffer);
	return NULL;
}
////
static int ksz_alloc_soft_desc(struct ksz_desc_info *desc_info, int transmit)
{
	desc_info->ring = kcalloc(desc_info->alloc, sizeof(struct ksz_desc),
				  GFP_KERNEL);
	if (!desc_info->ring)
		return 1;
	hw_init_desc(desc_info, transmit);
	return 0;
}
////
int mlx5e_attach_encap(struct mlx5e_priv *priv,
		       struct mlx5e_tc_flow *flow,
		       struct mlx5_flow_attr *attr,
		       struct net_device *mirred_dev,
		       int out_index,
		       struct netlink_ext_ack *extack,
		       struct net_device **encap_dev)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5e_tc_flow_parse_attr *parse_attr;
	const struct ip_tunnel_info *tun_info;
	const struct mlx5e_mpls_info *mpls_info;
	unsigned long tbl_time_before = 0;
	struct mlx5e_encap_entry *e;
	struct mlx5e_encap_key key;
	bool entry_created = false;
	unsigned short family;
	uintptr_t hash_key;
	int err = 0;

	parse_attr = attr->parse_attr;
	tun_info = parse_attr->tun_info[out_index];
	mpls_info = &parse_attr->mpls_info[out_index];
	family = ip_tunnel_info_af(tun_info);
	key.ip_tun_key = &tun_info->key;
	key.tc_tunnel = mlx5e_get_tc_tun(mirred_dev);
	if (!key.tc_tunnel) {
		NL_SET_ERR_MSG_MOD(extack, "Unsupported tunnel");
		return -EOPNOTSUPP;
	}

	hash_key = hash_encap_info(&key);

	mutex_lock(&esw->offloads.encap_tbl_lock);
	e = mlx5e_encap_get(priv, &key, hash_key);

	/* must verify if encap is valid or not */
	if (e) {
		/* Check that entry was not already attached to this flow */
		if (is_duplicated_encap_entry(priv, flow, out_index, e, extack)) {
			err = -EOPNOTSUPP;
			goto out_err;
		}

		mutex_unlock(&esw->offloads.encap_tbl_lock);
		wait_for_completion(&e->res_ready);

		/* Protect against concurrent neigh update. */
		mutex_lock(&esw->offloads.encap_tbl_lock);
		if (e->compl_result < 0) {
			err = -EREMOTEIO;
			goto out_err;
		}
		goto attach_flow;
	}

	e = kzalloc(sizeof(*e), GFP_KERNEL);
	if (!e) {
		err = -ENOMEM;
		goto out_err;
	}

	refcount_set(&e->refcnt, 1);
	init_completion(&e->res_ready);
	entry_created = true;
	INIT_LIST_HEAD(&e->route_list);

	tun_info = mlx5e_dup_tun_info(tun_info);
	if (!tun_info) {
		err = -ENOMEM;
		goto out_err_init;
	}
	e->tun_info = tun_info;
	memcpy(&e->mpls_info, mpls_info, sizeof(*mpls_info));
	err = mlx5e_tc_tun_init_encap_attr(mirred_dev, priv, e, extack);
	if (err)
		goto out_err_init;

	INIT_LIST_HEAD(&e->flows);
	hash_add_rcu(esw->offloads.encap_tbl, &e->encap_hlist, hash_key);
	tbl_time_before = mlx5e_route_tbl_get_last_update(priv);
	mutex_unlock(&esw->offloads.encap_tbl_lock);

	if (family == AF_INET)
		err = mlx5e_tc_tun_create_header_ipv4(priv, mirred_dev, e);
	else if (family == AF_INET6)
		err = mlx5e_tc_tun_create_header_ipv6(priv, mirred_dev, e);

	/* Protect against concurrent neigh update. */
	mutex_lock(&esw->offloads.encap_tbl_lock);
	complete_all(&e->res_ready);
	if (err) {
		e->compl_result = err;
		goto out_err;
	}
	e->compl_result = 1;

attach_flow:
	err = mlx5e_attach_encap_route(priv, flow, attr, e, entry_created,
				       tbl_time_before, out_index);
	if (err)
		goto out_err;

	err = mlx5e_set_int_port_tunnel(priv, attr, e, out_index);
	if (err == -EOPNOTSUPP) {
		/* If device doesn't support int port offload,
		 * redirect to uplink vport.
		 */
		mlx5_core_dbg(priv->mdev, "attaching int port as encap dev not supported, using uplink\n");
		err = 0;
	} else if (err) {
		goto out_err;
	}

	flow->encaps[out_index].e = e;
	list_add(&flow->encaps[out_index].list, &e->flows);
	flow->encaps[out_index].index = out_index;
	*encap_dev = e->out_dev;
	if (e->flags & MLX5_ENCAP_ENTRY_VALID) {
		attr->esw_attr->dests[out_index].pkt_reformat = e->pkt_reformat;
		attr->esw_attr->dests[out_index].flags |= MLX5_ESW_DEST_ENCAP_VALID;
	} else {
		flow_flag_set(flow, SLOW);
	}
	mutex_unlock(&esw->offloads.encap_tbl_lock);

	return err;

out_err:
	mutex_unlock(&esw->offloads.encap_tbl_lock);
	if (e)
		mlx5e_encap_put(priv, e);
	return err;

out_err_init:
	mutex_unlock(&esw->offloads.encap_tbl_lock);
	kfree(tun_info);
	kfree(e);
	return err;
}
////
STATIC int
xfs_iwalk_alloc(
	struct xfs_iwalk_ag	*iwag)
{
	size_t			size;

	ASSERT(iwag->recs == NULL);
	iwag->nr_recs = 0;

	/* Allocate a prefetch buffer for inobt records. */
	size = iwag->sz_recs * sizeof(struct xfs_inobt_rec_incore);
	iwag->recs = kmem_alloc(size, KM_MAYFAIL);
	if (iwag->recs == NULL)
		return -ENOMEM;

	return 0;
}
////
static int vmbus_alloc_requestor(struct vmbus_requestor *rqstor, u32 size)
{
	u64 *rqst_arr;
	unsigned long *bitmap;

	rqst_arr = request_arr_init(size);
	if (!rqst_arr)
		return -ENOMEM;

	bitmap = bitmap_zalloc(size, GFP_KERNEL);
	if (!bitmap) {
		kfree(rqst_arr);
		return -ENOMEM;
	}

	rqstor->req_arr = rqst_arr;
	rqstor->req_bitmap = bitmap;
	rqstor->size = size;
	rqstor->next_request_id = 0;
	spin_lock_init(&rqstor->req_lock);

	return 0;
}
////
static struct mlx5dr_action *create_ft_action(struct mlx5dr_domain *domain,
					      struct mlx5_flow_rule *dst)
{
	struct mlx5_flow_table *dest_ft = dst->dest_attr.ft;

	if (mlx5dr_is_fw_table(dest_ft))
		return mlx5dr_action_create_dest_flow_fw_table(domain, dest_ft);
	return mlx5dr_action_create_dest_table(dest_ft->fs_dr_table.dr_table);
}
////
static struct gss_pipe *gss_pipe_alloc(struct rpc_clnt *clnt,
		const char *name,
		const struct rpc_pipe_ops *upcall_ops)
{
	struct gss_pipe *p;
	int err = -ENOMEM;

	p = kmalloc(sizeof(*p), GFP_KERNEL);
	if (p == NULL)
		goto err;
	p->pipe = rpc_mkpipe_data(upcall_ops, RPC_PIPE_WAIT_FOR_OPEN);
	if (IS_ERR(p->pipe)) {
		err = PTR_ERR(p->pipe);
		goto err_free_gss_pipe;
	}
	p->name = name;
	p->clnt = clnt;
	kref_init(&p->kref);
	rpc_init_pipe_dir_object(&p->pdo,
			&gss_pipe_dir_object_ops,
			p);
	return p;
err_free_gss_pipe:
	kfree(p);
err:
	return ERR_PTR(err);
}
////
struct gru_thread_state *gru_alloc_thread_state(struct vm_area_struct *vma,
					int tsid)
{
	struct gru_vma_data *vdata = vma->vm_private_data;
	struct gru_thread_state *gts, *ngts;

	gts = gru_alloc_gts(vma, vdata->vd_cbr_au_count,
			    vdata->vd_dsr_au_count,
			    vdata->vd_tlb_preload_count,
			    vdata->vd_user_options, tsid);
	if (IS_ERR(gts))
		return gts;

	spin_lock(&vdata->vd_lock);
	ngts = gru_find_current_gts_nolock(vdata, tsid);
	if (ngts) {
		gts_drop(gts);
		gts = ngts;
		STAT(gts_double_allocate);
	} else {
		list_add(&gts->ts_next, &vdata->vd_head);
	}
	spin_unlock(&vdata->vd_lock);
	gru_dbg(grudev, "vma %p, gts %p\n", vma, gts);
	return gts;
}
////
static struct pxa_camera_format_xlate *pxa_mbus_build_fmts_xlate(
	struct v4l2_device *v4l2_dev, struct v4l2_subdev *subdev,
	int (*get_formats)(struct v4l2_device *, unsigned int,
			   struct pxa_camera_format_xlate *xlate))
{
	unsigned int i, fmts = 0, raw_fmts = 0;
	int ret;
	struct v4l2_subdev_mbus_code_enum code = {
		.which = V4L2_SUBDEV_FORMAT_ACTIVE,
	};
	struct pxa_camera_format_xlate *user_formats;

	while (!v4l2_subdev_call(subdev, pad, enum_mbus_code, NULL, &code)) {
		raw_fmts++;
		code.index++;
	}

	for (i = 0; i < raw_fmts; i++) {
		ret = get_formats(v4l2_dev, i, NULL);
		if (ret < 0)
			return ERR_PTR(ret);
		fmts += ret;
	}

	if (!fmts)
		return ERR_PTR(-ENXIO);

	user_formats = kcalloc(fmts + 1, sizeof(*user_formats), GFP_KERNEL);
	if (!user_formats)
		return ERR_PTR(-ENOMEM);

	fmts = 0;
	for (i = 0; i < raw_fmts; i++) {
		ret = get_formats(v4l2_dev, i, user_formats + fmts);
		if (ret < 0)
			goto egfmt;
		fmts += ret;
	}
	user_formats[fmts].code = 0;

	return user_formats;
egfmt:
	kfree(user_formats);
	return ERR_PTR(ret);
}
////
static inline const int16_t *fir16_create(struct fir16_state_t *fir,
					      const int16_t *coeffs, int taps)
{
	fir->taps = taps;
	fir->curr_pos = taps - 1;
	fir->coeffs = coeffs;
	fir->history = kcalloc(taps, sizeof(int16_t), GFP_KERNEL);
	return fir->history;
}
////
static struct brcmf_usbreq *
brcmf_usbdev_qinit(struct list_head *q, int qsize)
{
	int i;
	struct brcmf_usbreq *req, *reqs;

	reqs = kcalloc(qsize, sizeof(struct brcmf_usbreq), GFP_ATOMIC);
	if (reqs == NULL)
		return NULL;

	req = reqs;

	for (i = 0; i < qsize; i++) {
		req->urb = usb_alloc_urb(0, GFP_ATOMIC);
		if (!req->urb)
			goto fail;

		INIT_LIST_HEAD(&req->list);
		list_add_tail(&req->list, q);
		req++;
	}
	return reqs;
fail:
	brcmf_err("fail!\n");
	while (!list_empty(q)) {
		req = list_entry(q->next, struct brcmf_usbreq, list);
		if (req)
			usb_free_urb(req->urb);
		list_del(q->next);
	}
	kfree(reqs);
	return NULL;

}
////
struct drm_property_blob *
drm_property_create_blob(struct drm_device *dev, size_t length,
			 const void *data)
{
	struct drm_property_blob *blob;
	int ret;

	if (!length || length > INT_MAX - sizeof(struct drm_property_blob))
		return ERR_PTR(-EINVAL);

	blob = kvzalloc(sizeof(struct drm_property_blob)+length, GFP_KERNEL);
	if (!blob)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&blob->head_file);
	blob->data = (void *)blob + sizeof(*blob);
	blob->length = length;
	blob->dev = dev;

	if (data)
		memcpy(blob->data, data, length);

	ret = __drm_mode_object_add(dev, &blob->base, DRM_MODE_OBJECT_BLOB,
				    true, drm_property_free_blob);
	if (ret) {
		kvfree(blob);
		return ERR_PTR(-EINVAL);
	}

	mutex_lock(&dev->mode_config.blob_lock);
	list_add_tail(&blob->head_global,
	              &dev->mode_config.property_blob_list);
	mutex_unlock(&dev->mode_config.blob_lock);

	return blob;
}
////
static struct p9_rdir *v9fs_alloc_rdir_buf(struct file *filp, int buflen)
{
	struct p9_fid *fid = filp->private_data;

	if (!fid->rdir)
		fid->rdir = kzalloc(sizeof(struct p9_rdir) + buflen, GFP_KERNEL);
	return fid->rdir;
}
////
struct ieee80211_hw *p54_init_common(size_t priv_data_len)
{
	struct ieee80211_hw *dev;
	struct p54_common *priv;

	dev = ieee80211_alloc_hw(priv_data_len, &p54_ops);
	if (!dev)
		return NULL;

	priv = dev->priv;
	priv->hw = dev;
	priv->mode = NL80211_IFTYPE_UNSPECIFIED;
	priv->basic_rate_mask = 0x15f;
	spin_lock_init(&priv->tx_stats_lock);
	skb_queue_head_init(&priv->tx_queue);
	skb_queue_head_init(&priv->tx_pending);
	ieee80211_hw_set(dev, REPORTS_TX_ACK_STATUS);
	ieee80211_hw_set(dev, MFP_CAPABLE);
	ieee80211_hw_set(dev, PS_NULLFUNC_STACK);
	ieee80211_hw_set(dev, SUPPORTS_PS);
	ieee80211_hw_set(dev, RX_INCLUDES_FCS);
	ieee80211_hw_set(dev, SIGNAL_DBM);

	dev->wiphy->interface_modes = BIT(NL80211_IFTYPE_STATION) |
				      BIT(NL80211_IFTYPE_ADHOC) |
				      BIT(NL80211_IFTYPE_AP) |
				      BIT(NL80211_IFTYPE_MESH_POINT);

	priv->beacon_req_id = cpu_to_le32(0);
	priv->tx_stats[P54_QUEUE_BEACON].limit = 1;
	priv->tx_stats[P54_QUEUE_FWSCAN].limit = 1;
	priv->tx_stats[P54_QUEUE_MGMT].limit = 3;
	priv->tx_stats[P54_QUEUE_CAB].limit = 3;
	priv->tx_stats[P54_QUEUE_DATA].limit = 5;
	dev->queues = 1;
	priv->noise = -94;
	/*
	 * We support at most 8 tries no matter which rate they're at,
	 * we cannot support max_rates * max_rate_tries as we set it
	 * here, but setting it correctly to 4/2 or so would limit us
	 * artificially if the RC algorithm wants just two rates, so
	 * let's say 4/7, we'll redistribute it at TX time, see the
	 * comments there.
	 */
	dev->max_rates = 4;
	dev->max_rate_tries = 7;
	dev->extra_tx_headroom = sizeof(struct p54_hdr) + 4 +
				 sizeof(struct p54_tx_data);

	/*
	 * For now, disable PS by default because it affects
	 * link stability significantly.
	 */
	dev->wiphy->flags &= ~WIPHY_FLAG_PS_ON_BY_DEFAULT;

	mutex_init(&priv->conf_mutex);
	mutex_init(&priv->eeprom_mutex);
	init_completion(&priv->stat_comp);
	init_completion(&priv->eeprom_comp);
	init_completion(&priv->beacon_comp);
	INIT_DELAYED_WORK(&priv->work, p54_work);

	eth_broadcast_addr(priv->mc_maclist[0]);
	priv->curchan = NULL;
	p54_reset_stats(priv);
	return dev;
}