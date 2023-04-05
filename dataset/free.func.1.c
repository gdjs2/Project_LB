static void intel_iommu_free_atsr(struct dmar_atsr_unit *atsru)
{
	dmar_free_dev_scope(&atsru->devices, &atsru->devices_cnt);
	kfree(atsru);
}
////
void regmap_del_irq_chip(int irq, struct regmap_irq_chip_data *d)
{
	unsigned int virq;
	int i, hwirq;

	if (!d)
		return;

	free_irq(irq, d);

	for (hwirq = 0; hwirq < d->chip->num_irqs; hwirq++) {
		if (!d->chip->irqs[hwirq].mask)
			continue;

		virq = irq_find_mapping(d->domain, hwirq);
		if (virq)
			irq_dispose_mapping(virq);
	}

	irq_domain_remove(d->domain);
	kfree(d->type_buf);
	kfree(d->type_buf_def);
	kfree(d->wake_buf);
	kfree(d->mask_buf_def);
	kfree(d->mask_buf);
	kfree(d->status_reg_buf);
	kfree(d->status_buf);
	if (d->config_buf) {
		for (i = 0; i < d->chip->num_config_bases; i++)
			kfree(d->config_buf[i]);
		kfree(d->config_buf);
	}
	kfree(d);
}
////
void agp_generic_destroy_pages(struct agp_memory *mem)
{
	int i;
	struct page *page;

	if (!mem)
		return;

#ifdef CONFIG_X86
	set_pages_array_wb(mem->pages, mem->page_count);
#endif

	for (i = 0; i < mem->page_count; i++) {
		page = mem->pages[i];

#ifndef CONFIG_X86
		unmap_page_from_agp(page);
#endif
		put_page(page);
		__free_page(page);
		atomic_dec(&agp_bridge->current_memory_agp);
		mem->pages[i] = NULL;
	}
}
////
static void drm_client_modeset_release(struct drm_client_dev *client)
{
	struct drm_mode_set *modeset;
	unsigned int i;

	drm_client_for_each_modeset(modeset, client) {
		drm_mode_destroy(client->dev, modeset->mode);
		modeset->mode = NULL;
		modeset->fb = NULL;

		for (i = 0; i < modeset->num_connectors; i++) {
			drm_connector_put(modeset->connectors[i]);
			modeset->connectors[i] = NULL;
		}
		modeset->num_connectors = 0;
	}
}
////
void __mpol_put(struct mempolicy *p)
{
	if (!atomic_dec_and_test(&p->refcnt))
		return;
	kmem_cache_free(policy_cache, p);
}
////
static void ioc_cpd_free(struct blkcg_policy_data *cpd)
{
	kfree(container_of(cpd, struct ioc_cgrp, cpd));
}
////
static void free_substream(struct snd_usb_substream *subs)
{
	struct audioformat *fp, *n;

	if (!subs->num_formats)
		return; 
	list_for_each_entry_safe(fp, n, &subs->fmt_list, list)
		audioformat_free(fp);
	kfree(subs->str_pd);
	snd_media_stream_delete(subs);
}
////
static void snd_pcm_oss_release_substream(struct snd_pcm_substream *substream)
{
	snd_pcm_oss_release_buffers(substream);
	substream->oss.oss = 0;
}
////
void free_mqd_hiq_sdma(struct mqd_manager *mm, void *mqd,
			struct kfd_mem_obj *mqd_mem_obj)
{
	WARN_ON(!mqd_mem_obj->gtt_mem);
	kfree(mqd_mem_obj);
}
////
static void batadv_nc_packet_free(struct batadv_nc_packet *nc_packet,
				  bool dropped)
{
	if (dropped)
		kfree_skb(nc_packet->skb);
	else
		consume_skb(nc_packet->skb);

	batadv_nc_path_put(nc_packet->nc_path);
	kfree(nc_packet);
}
////
void tb_ctl_free(struct tb_ctl *ctl)
{
	int i;

	if (!ctl)
		return;

	if (ctl->rx)
		tb_ring_free(ctl->rx);
	if (ctl->tx)
		tb_ring_free(ctl->tx);

	for (i = 0; i < TB_CTL_RX_PKG_COUNT; i++)
		tb_ctl_pkg_free(ctl->rx_packets[i]);

	dma_pool_destroy(ctl->frame_pool);
	kfree(ctl);
}
////
static void rdtgroup_remove(struct rdtgroup *rdtgrp)
{
	kernfs_put(rdtgrp->kn);
	kfree(rdtgrp);
}
////
static void __ipmi_bmc_unregister(struct ipmi_smi *intf)
{
	struct bmc_device *bmc = intf->bmc;

	if (!intf->bmc_registered)
		return;

	sysfs_remove_link(&intf->si_dev->kobj, "bmc");
	sysfs_remove_link(&bmc->pdev.dev.kobj, intf->my_dev_name);
	kfree(intf->my_dev_name);
	intf->my_dev_name = NULL;

	mutex_lock(&bmc->dyn_mutex);
	list_del(&intf->bmc_link);
	mutex_unlock(&bmc->dyn_mutex);
	intf->bmc = &intf->tmp_bmc;
	kref_put(&bmc->usecount, cleanup_bmc_device);
	intf->bmc_registered = false;
}
////
static void cls_bpf_free_parms(struct cls_bpf_prog *prog)
{
	if (cls_bpf_is_ebpf(prog))
		bpf_prog_put(prog->filter);
	else
		bpf_prog_destroy(prog->filter);

	kfree(prog->bpf_name);
	kfree(prog->bpf_ops);
}
////
static inline void sk_psock_cork_free(struct sk_psock *psock)
{
	if (psock->cork) {
		sk_msg_free(psock->sk, psock->cork);
		kfree(psock->cork);
		psock->cork = NULL;
	}
}
////
static void tda10086_release(struct dvb_frontend* fe)
{
	struct tda10086_state *state = fe->demodulator_priv;
	tda10086_sleep(fe);
	kfree(state);
}
////
static void qede_free_mem_txq(struct qede_dev *edev, struct qede_tx_queue *txq)
{
	if (txq->is_xdp)
		kfree(txq->sw_tx_ring.xdp);
	else
		kfree(txq->sw_tx_ring.skbs);

	edev->ops->common->chain_free(edev->cdev, &txq->tx_pbl);
}
////
static void vm_del_vq(struct virtqueue *vq)
{
	struct virtio_mmio_device *vm_dev = to_virtio_mmio_device(vq->vdev);
	struct virtio_mmio_vq_info *info = vq->priv;
	unsigned long flags;
	unsigned int index = vq->index;

	spin_lock_irqsave(&vm_dev->lock, flags);
	list_del(&info->node);
	spin_unlock_irqrestore(&vm_dev->lock, flags);

	writel(index, vm_dev->base + VIRTIO_MMIO_QUEUE_SEL);
	if (vm_dev->version == 1) {
		writel(0, vm_dev->base + VIRTIO_MMIO_QUEUE_PFN);
	} else {
		writel(0, vm_dev->base + VIRTIO_MMIO_QUEUE_READY);
		WARN_ON(readl(vm_dev->base + VIRTIO_MMIO_QUEUE_READY));
	}

	vring_del_virtqueue(vq);

	kfree(info);
}
////
static void
_transport_unmap_smp_buffer(struct device *dev, struct bsg_buffer *buf,
		dma_addr_t dma_addr, void *p)
{
	if (p)
		dma_free_coherent(dev, buf->payload_len, p, dma_addr);
	else
		dma_unmap_sg(dev, buf->sg_list, 1, DMA_BIDIRECTIONAL);
}
////
static void cdnsp_ring_free(struct cdnsp_device *pdev, struct cdnsp_ring *ring)
{
	if (!ring)
		return;

	trace_cdnsp_ring_free(ring);

	if (ring->first_seg) {
		if (ring->type == TYPE_STREAM)
			cdnsp_remove_stream_mapping(ring);

		cdnsp_free_segments_for_ring(pdev, ring->first_seg);
	}

	kfree(ring);
}
////
static void release_resources(struct gpmi_nand_data *this)
{
	release_dma_channels(this);
}
////
void mlx5dr_send_ring_free(struct mlx5dr_domain *dmn,
			   struct mlx5dr_send_ring *send_ring)
{
	dr_destroy_qp(dmn->mdev, send_ring->qp);
	dr_destroy_cq(dmn->mdev, send_ring->cq);
	dr_dereg_mr(dmn->mdev, send_ring->sync_mr);
	dr_dereg_mr(dmn->mdev, send_ring->mr);
	kfree(send_ring->buf);
	kfree(send_ring);
}
////
void mpi_point_release(MPI_POINT p)
{
	if (p) {
		mpi_point_free_parts(p);
		kfree(p);
	}
}
////
static void s5h1420_release(struct dvb_frontend* fe)
{
	struct s5h1420_state* state = fe->demodulator_priv;
	i2c_del_adapter(&state->tuner_i2c_adapter);
	kfree(state);
}
////
static void __rb_free_aux(struct perf_buffer *rb)
{
	int pg;

	WARN_ON_ONCE(in_atomic());

	if (rb->aux_priv) {
		rb->free_aux(rb->aux_priv);
		rb->free_aux = NULL;
		rb->aux_priv = NULL;
	}

	if (rb->aux_nr_pages) {
		for (pg = 0; pg < rb->aux_nr_pages; pg++)
			rb_free_aux_page(rb, pg);

		kfree(rb->aux_pages);
		rb->aux_nr_pages = 0;
	}
}
////
static void cxgb4_free_eosw_txq(struct net_device *dev,
				struct sge_eosw_txq *eosw_txq)
{
	spin_lock_bh(&eosw_txq->lock);
	cxgb4_clean_eosw_txq(dev, eosw_txq);
	kfree(eosw_txq->desc);
	spin_unlock_bh(&eosw_txq->lock);
	tasklet_kill(&eosw_txq->qresume_tsk);
}
////
static void node_access_release(struct device *dev)
{
	kfree(to_access_nodes(dev));
}
////
static void ns2501_destroy(struct intel_dvo_device *dvo)
{
	struct ns2501_priv *ns = dvo->dev_priv;

	if (ns) {
		kfree(ns);
		dvo->dev_priv = NULL;
	}
}
////
static void __fprog_destroy(struct sock_fprog_kern *fprog)
{
	kfree(fprog->filter);
	kfree(fprog);
}
////
void snd_pcm_detach_substream(struct snd_pcm_substream *substream)
{
	struct snd_pcm_runtime *runtime;

	if (PCM_RUNTIME_CHECK(substream))
		return;
	runtime = substream->runtime;
	if (runtime->private_free != NULL)
		runtime->private_free(runtime);
	free_pages_exact(runtime->status,
		       PAGE_ALIGN(sizeof(struct snd_pcm_mmap_status)));
	free_pages_exact(runtime->control,
		       PAGE_ALIGN(sizeof(struct snd_pcm_mmap_control)));
	kfree(runtime->hw_constraints.rules);
	if (substream->timer) {
		spin_lock_irq(&substream->timer->lock);
		substream->runtime = NULL;
		spin_unlock_irq(&substream->timer->lock);
	} else {
		substream->runtime = NULL;
	}
	mutex_destroy(&runtime->buffer_mutex);
	snd_fasync_free(runtime->fasync);
	kfree(runtime);
	put_pid(substream->pid);
	substream->pid = NULL;
	substream->pstr->substream_opened--;
}
////
void otx2_free_cints(struct otx2_nic *pfvf, int n)
{
	struct otx2_qset *qset = &pfvf->qset;
	struct otx2_hw *hw = &pfvf->hw;
	int irq, qidx;

	for (qidx = 0, irq = hw->nix_msixoff + NIX_LF_CINT_VEC_START;
	     qidx < n;
	     qidx++, irq++) {
		int vector = pci_irq_vector(pfvf->pdev, irq);

		irq_set_affinity_hint(vector, NULL);
		free_cpumask_var(hw->affinity_mask[irq]);
		free_irq(vector, &qset->napi[qidx]);
	}
}
////
void ir_raw_event_free(struct rc_dev *dev)
{
	if (!dev)
		return;

	kfree(dev->raw);
	dev->raw = NULL;
}
////
static void stream_free(struct xen_snd_front_pcm_stream_info *stream)
{
	xen_front_pgdir_shbuf_unmap(&stream->shbuf);
	xen_front_pgdir_shbuf_free(&stream->shbuf);
	if (stream->buffer)
		free_pages_exact(stream->buffer, stream->buffer_sz);
	kfree(stream->pages);
	stream_clear(stream);
}
////
void
xprt_rdma_free_addresses(struct rpc_xprt *xprt)
{
	unsigned int i;

	for (i = 0; i < RPC_DISPLAY_MAX; i++)
		switch (i) {
		case RPC_DISPLAY_PROTO:
		case RPC_DISPLAY_NETID:
			continue;
		default:
			kfree(xprt->address_strings[i]);
		}
}
////
static void
mlxsw_sp_acl_atcam_lkey_id_destroy(struct mlxsw_sp_acl_atcam_region *aregion,
				   struct mlxsw_sp_acl_atcam_lkey_id *lkey_id)
{
	struct mlxsw_sp_acl_atcam_region_12kb *region_12kb = aregion->priv;
	u32 id = lkey_id->id;

	rhashtable_remove_fast(&region_12kb->lkey_ht, &lkey_id->ht_node,
			       mlxsw_sp_acl_atcam_lkey_id_ht_params);
	kfree(lkey_id);
	__clear_bit(id, region_12kb->used_lkey_id);
}
////
static void cyberpro_free_fb_info(struct cfb_info *cfb)
{
	if (cfb) {
		/*
		 * Free the colourmap
		 */
		fb_alloc_cmap(&cfb->fb.cmap, 0, 0);

		kfree(cfb);
	}
}
////
static void free_param_target(struct netconsole_target *nt)
{
	netpoll_cleanup(&nt->np);
	kfree(nt);
}
////
static void otx2_pfvf_mbox_destroy(struct otx2_nic *pf)
{
	struct mbox *mbox = &pf->mbox_pfvf[0];

	if (!mbox)
		return;

	if (pf->mbox_pfvf_wq) {
		destroy_workqueue(pf->mbox_pfvf_wq);
		pf->mbox_pfvf_wq = NULL;
	}

	if (mbox->mbox.hwbase)
		iounmap(mbox->mbox.hwbase);

	otx2_mbox_destroy(&mbox->mbox);
}
////
static inline void iowarrior_delete(struct iowarrior *dev)
{
	dev_dbg(&dev->interface->dev, "minor %d\n", dev->minor);
	kfree(dev->int_in_buffer);
	usb_free_urb(dev->int_in_urb);
	kfree(dev->read_queue);
	usb_put_intf(dev->interface);
	kfree(dev);
}
////
static void free_page_arrays(struct hinic_wqs *wqs)
{
	struct hinic_hwif *hwif = wqs->hwif;
	struct pci_dev *pdev = hwif->pdev;

	devm_kfree(&pdev->dev, wqs->shadow_page_vaddr);
	devm_kfree(&pdev->dev, wqs->page_vaddr);
	devm_kfree(&pdev->dev, wqs->page_paddr);
}
////
static void brcmf_fw_free_request(struct brcmf_fw_request *req)
{
	struct brcmf_fw_item *item;
	int i;

	for (i = 0, item = &req->items[0]; i < req->n_items; i++, item++) {
		if (item->type == BRCMF_FW_TYPE_BINARY)
			release_firmware(item->binary);
		else if (item->type == BRCMF_FW_TYPE_NVRAM)
			brcmf_fw_nvram_free(item->nv_data.data);
	}
	kfree(req);
}
////
static void bnxt_free_tpa_info(struct bnxt *bp)
{
	int i, j;

	for (i = 0; i < bp->rx_nr_rings; i++) {
		struct bnxt_rx_ring_info *rxr = &bp->rx_ring[i];

		kfree(rxr->rx_tpa_idx_map);
		rxr->rx_tpa_idx_map = NULL;
		if (rxr->rx_tpa) {
			for (j = 0; j < bp->max_tpa; j++) {
				kfree(rxr->rx_tpa[j].agg_arr);
				rxr->rx_tpa[j].agg_arr = NULL;
			}
		}
		kfree(rxr->rx_tpa);
		rxr->rx_tpa = NULL;
	}
}
////
static void r820t_release(struct dvb_frontend *fe)
{
	struct r820t_priv *priv = fe->tuner_priv;

	tuner_dbg("%s:\n", __func__);

	mutex_lock(&r820t_list_mutex);

	if (priv)
		hybrid_tuner_release_state(priv);

	mutex_unlock(&r820t_list_mutex);

	fe->tuner_priv = NULL;
}
////
void spi_mem_dirmap_destroy(struct spi_mem_dirmap_desc *desc)
{
	struct spi_controller *ctlr = desc->mem->spi->controller;

	if (!desc->nodirmap && ctlr->mem_ops && ctlr->mem_ops->dirmap_destroy)
		ctlr->mem_ops->dirmap_destroy(desc);

	kfree(desc);
}
////
static void scratchpad_free(struct xhci_hcd *xhci)
{
	int num_sp;
	int i;
	struct device *dev = xhci_to_hcd(xhci)->self.sysdev;

	if (!xhci->scratchpad)
		return;

	num_sp = HCS_MAX_SCRATCHPAD(xhci->hcs_params2);

	for (i = 0; i < num_sp; i++) {
		dma_free_coherent(dev, xhci->page_size,
				    xhci->scratchpad->sp_buffers[i],
				    xhci->scratchpad->sp_array[i]);
	}
	kfree(xhci->scratchpad->sp_buffers);
	dma_free_coherent(dev, num_sp * sizeof(u64),
			    xhci->scratchpad->sp_array,
			    xhci->scratchpad->sp_dma);
	kfree(xhci->scratchpad);
	xhci->scratchpad = NULL;
}
////
static void mlx4_en_free_resources(struct mlx4_en_priv *priv)
{
	int i, t;

#ifdef CONFIG_RFS_ACCEL
	priv->dev->rx_cpu_rmap = NULL;
#endif

	for (t = 0; t < MLX4_EN_NUM_TX_TYPES; t++) {
		for (i = 0; i < priv->tx_ring_num[t]; i++) {
			if (priv->tx_ring[t] && priv->tx_ring[t][i])
				mlx4_en_destroy_tx_ring(priv,
							&priv->tx_ring[t][i]);
			if (priv->tx_cq[t] && priv->tx_cq[t][i])
				mlx4_en_destroy_cq(priv, &priv->tx_cq[t][i]);
		}
		kfree(priv->tx_ring[t]);
		kfree(priv->tx_cq[t]);
	}

	for (i = 0; i < priv->rx_ring_num; i++) {
		if (priv->rx_ring[i])
			mlx4_en_destroy_rx_ring(priv, &priv->rx_ring[i],
				priv->prof->rx_ring_size, priv->stride);
		if (priv->rx_cq[i])
			mlx4_en_destroy_cq(priv, &priv->rx_cq[i]);
	}

}
////
void __drm_atomic_helper_plane_destroy_state(struct drm_plane_state *state)
{
	if (state->fb)
		drm_framebuffer_put(state->fb);

	if (state->fence)
		dma_fence_put(state->fence);

	if (state->commit)
		drm_crtc_commit_put(state->commit);

	drm_property_blob_put(state->fb_damage_clips);
}