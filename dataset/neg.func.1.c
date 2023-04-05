static int genfs_read(struct policydb *p, void *fp)
{
	int i, j, rc;
	u32 nel, nel2, len, len2;
	__le32 buf[1];
	struct ocontext *l, *c;
	struct ocontext *newc = NULL;
	struct genfs *genfs_p, *genfs;
	struct genfs *newgenfs = NULL;

	rc = next_entry(buf, fp, sizeof(u32));
	if (rc)
		return rc;
	nel = le32_to_cpu(buf[0]);

	for (i = 0; i < nel; i++) {
		rc = next_entry(buf, fp, sizeof(u32));
		if (rc)
			goto out;
		len = le32_to_cpu(buf[0]);

		rc = -ENOMEM;
		newgenfs = kzalloc(sizeof(*newgenfs), GFP_KERNEL);
		if (!newgenfs)
			goto out;

		rc = str_read(&newgenfs->fstype, GFP_KERNEL, fp, len);
		if (rc)
			goto out;

		for (genfs_p = NULL, genfs = p->genfs; genfs;
		     genfs_p = genfs, genfs = genfs->next) {
			rc = -EINVAL;
			if (strcmp(newgenfs->fstype, genfs->fstype) == 0) {
				pr_err("SELinux:  dup genfs fstype %s\n",
				       newgenfs->fstype);
				goto out;
			}
			if (strcmp(newgenfs->fstype, genfs->fstype) < 0)
				break;
		}
		newgenfs->next = genfs;
		if (genfs_p)
			genfs_p->next = newgenfs;
		else
			p->genfs = newgenfs;
		genfs = newgenfs;
		newgenfs = NULL;

		rc = next_entry(buf, fp, sizeof(u32));
		if (rc)
			goto out;

		nel2 = le32_to_cpu(buf[0]);
		for (j = 0; j < nel2; j++) {
			rc = next_entry(buf, fp, sizeof(u32));
			if (rc)
				goto out;
			len = le32_to_cpu(buf[0]);

			rc = -ENOMEM;
			newc = kzalloc(sizeof(*newc), GFP_KERNEL);
			if (!newc)
				goto out;

			rc = str_read(&newc->u.name, GFP_KERNEL, fp, len);
			if (rc)
				goto out;

			rc = next_entry(buf, fp, sizeof(u32));
			if (rc)
				goto out;

			newc->v.sclass = le32_to_cpu(buf[0]);
			rc = context_read_and_validate(&newc->context[0], p, fp);
			if (rc)
				goto out;

			for (l = NULL, c = genfs->head; c;
			     l = c, c = c->next) {
				rc = -EINVAL;
				if (!strcmp(newc->u.name, c->u.name) &&
				    (!c->v.sclass || !newc->v.sclass ||
				     newc->v.sclass == c->v.sclass)) {
					pr_err("SELinux:  dup genfs entry (%s,%s)\n",
					       genfs->fstype, c->u.name);
					goto out;
				}
				len = strlen(newc->u.name);
				len2 = strlen(c->u.name);
				if (len > len2)
					break;
			}

			newc->next = c;
			if (l)
				l->next = newc;
			else
				genfs->head = newc;
			newc = NULL;
		}
	}
	rc = 0;
out:
	if (newgenfs) {
		kfree(newgenfs->fstype);
		kfree(newgenfs);
	}
	ocontext_destroy(newc, OCON_FSUSE);

	return rc;
}
////
static int start_ms350_cam(struct gspca_dev *gspca_dev)
{
	struct init_command ms350_start_commands[] = {
		{{0x0c, 0x01, 0x00, 0x00, 0x00, 0x00}, 4},
		{{0x16, 0x01, 0x00, 0x00, 0x00, 0x00}, 4},
		{{0x13, 0x20, 0x01, 0x00, 0x00, 0x00}, 4},
		{{0x13, 0x21, 0x01, 0x00, 0x00, 0x00}, 4},
		{{0x13, 0x22, 0x01, 0x04, 0x00, 0x00}, 4},
		{{0x13, 0x23, 0x01, 0x03, 0x00, 0x00}, 4},
		{{0x13, 0x24, 0x01, 0x00, 0x00, 0x00}, 4},
		{{0x13, 0x25, 0x01, 0x16, 0x00, 0x00}, 4},
		{{0x13, 0x26, 0x01, 0x12, 0x00, 0x00}, 4},
		{{0x13, 0x27, 0x01, 0x28, 0x00, 0x00}, 4},
		{{0x13, 0x28, 0x01, 0x09, 0x00, 0x00}, 4},
		{{0x13, 0x29, 0x01, 0x00, 0x00, 0x00}, 4},
		{{0x13, 0x2a, 0x01, 0x00, 0x00, 0x00}, 4},
		{{0x13, 0x2b, 0x01, 0x00, 0x00, 0x00}, 4},
		{{0x13, 0x2c, 0x01, 0x02, 0x00, 0x00}, 4},
		{{0x13, 0x2d, 0x01, 0x03, 0x00, 0x00}, 4},
		{{0x13, 0x2e, 0x01, 0x0f, 0x00, 0x00}, 4},
		{{0x13, 0x2f, 0x01, 0x0c, 0x00, 0x00}, 4},
		{{0x12, 0x34, 0x01, 0x00, 0x00, 0x00}, 4},
		{{0x13, 0x34, 0x01, 0xa1, 0x00, 0x00}, 4},
		{{0x13, 0x35, 0x01, 0x00, 0x00, 0x00}, 4},
		{{0x11, 0x00, 0x01, 0x00, 0x00, 0x00}, 4},
		{{0x11, 0x01, 0x70, 0x00, 0x00, 0x00}, 4},
		{{0x11, 0x02, 0x05, 0x00, 0x00, 0x00}, 4},
		{{0x11, 0x03, 0x5d, 0x00, 0x00, 0x00}, 4},
		{{0x11, 0x04, 0x07, 0x00, 0x00, 0x00}, 4},
		{{0x11, 0x05, 0x25, 0x00, 0x00, 0x00}, 4},
		{{0x11, 0x06, 0x00, 0x00, 0x00, 0x00}, 4},
		{{0x11, 0x07, 0x09, 0x00, 0x00, 0x00}, 4},
		{{0x11, 0x08, 0x01, 0x00, 0x00, 0x00}, 4},
		{{0x11, 0x09, 0x00, 0x00, 0x00, 0x00}, 4},
		{{0x11, 0x0a, 0x00, 0x00, 0x00, 0x00}, 4},
		{{0x11, 0x0b, 0x01, 0x00, 0x00, 0x00}, 4},
		{{0x11, 0x0c, 0x00, 0x00, 0x00, 0x00}, 4},
		{{0x11, 0x0d, 0x0c, 0x00, 0x00, 0x00}, 4},
		{{0x11, 0x0e, 0x01, 0x00, 0x00, 0x00}, 4},
		{{0x11, 0x0f, 0x00, 0x00, 0x00, 0x00}, 4},
		{{0x11, 0x10, 0x00, 0x00, 0x00, 0x00}, 4},
		{{0x11, 0x11, 0x00, 0x00, 0x00, 0x00}, 4},
		{{0x11, 0x12, 0x00, 0x00, 0x00, 0x00}, 4},
		{{0x11, 0x13, 0x63, 0x00, 0x00, 0x00}, 4},
		{{0x11, 0x15, 0x70, 0x00, 0x00, 0x00}, 4},
		{{0x11, 0x18, 0x00, 0x00, 0x00, 0x00}, 4},
		{{0x11, 0x11, 0x01, 0x00, 0x00, 0x00}, 4},
		{{0x13, 0x25, 0x01, 0x28, 0x00, 0x00}, 4},
		{{0x13, 0x26, 0x01, 0x1e, 0x00, 0x00}, 4},
		{{0x13, 0x28, 0x01, 0x09, 0x00, 0x00}, 4},
		{{0x13, 0x27, 0x01, 0x28, 0x00, 0x00}, 4},
		{{0x13, 0x29, 0x01, 0x40, 0x00, 0x00}, 4},
		{{0x13, 0x2c, 0x01, 0x02, 0x00, 0x00}, 4},
		{{0x13, 0x2d, 0x01, 0x03, 0x00, 0x00}, 4},
		{{0x13, 0x2e, 0x01, 0x0f, 0x00, 0x00}, 4},
		{{0x13, 0x2f, 0x01, 0x0c, 0x00, 0x00}, 4},
		{{0x1b, 0x02, 0x05, 0x00, 0x00, 0x00}, 1},
		{{0x1b, 0x11, 0x01, 0x00, 0x00, 0x00}, 1},
		{{0x20, 0x18, 0x00, 0x00, 0x00, 0x00}, 1},
		{{0x1b, 0x02, 0x0a, 0x00, 0x00, 0x00}, 1},
		{{0x1b, 0x11, 0x01, 0x00, 0x00, 0x00}, 0},
	};

	return run_start_commands(gspca_dev, ms350_start_commands,
				  ARRAY_SIZE(ms350_start_commands));
}
////
int pxa2xx_soc_pcm_hw_params(struct snd_soc_component *component,
			     struct snd_pcm_substream *substream,
			     struct snd_pcm_hw_params *params)
{
	return pxa2xx_pcm_hw_params(substream, params);
}
////
static void update_balloon_size_func(struct work_struct *work)
{
	struct virtio_balloon *vb;
	s64 diff;

	vb = container_of(work, struct virtio_balloon,
			  update_balloon_size_work);
	diff = towards_target(vb);

	if (!diff)
		return;

	if (diff > 0)
		diff -= fill_balloon(vb, diff);
	else
		diff += leak_balloon(vb, -diff);
	update_balloon_size(vb);

	if (diff)
		queue_work(system_freezable_wq, work);
}
////
int
nv50_disp_dmac_bind(struct nvkm_disp_chan *chan, struct nvkm_object *object, u32 handle)
{
	return nvkm_ramht_insert(chan->disp->ramht, object, chan->chid.user, -10, handle,
				 chan->chid.user << 28 | chan->chid.user);
}
////
int cxd2880_tnrdmd_dvbt2_mon_snr(struct cxd2880_tnrdmd *tnr_dmd,
				 int *snr)
{
	u16 reg_value = 0;
	int ret;

	if (!tnr_dmd || !snr)
		return -EINVAL;

	*snr = -1000 * 1000;

	if (tnr_dmd->diver_mode == CXD2880_TNRDMD_DIVERMODE_SUB)
		return -EINVAL;

	if (tnr_dmd->state != CXD2880_TNRDMD_STATE_ACTIVE)
		return -EINVAL;

	if (tnr_dmd->sys != CXD2880_DTV_SYS_DVBT2)
		return -EINVAL;

	if (tnr_dmd->diver_mode == CXD2880_TNRDMD_DIVERMODE_SINGLE) {
		ret = dvbt2_read_snr_reg(tnr_dmd, &reg_value);
		if (ret)
			return ret;

		ret = dvbt2_calc_snr(tnr_dmd, reg_value, snr);
	} else {
		int snr_main = 0;
		int snr_sub = 0;

		ret =
		    cxd2880_tnrdmd_dvbt2_mon_snr_diver(tnr_dmd, snr, &snr_main,
						       &snr_sub);
	}

	return ret;
}
////
int cxd2880_tnrdmd_dvbt_mon_snr(struct cxd2880_tnrdmd *tnr_dmd,
				int *snr)
{
	u16 reg_value = 0;
	int ret;

	if (!tnr_dmd || !snr)
		return -EINVAL;

	*snr = -1000 * 1000;

	if (tnr_dmd->diver_mode == CXD2880_TNRDMD_DIVERMODE_SUB)
		return -EINVAL;

	if (tnr_dmd->state != CXD2880_TNRDMD_STATE_ACTIVE)
		return -EINVAL;

	if (tnr_dmd->sys != CXD2880_DTV_SYS_DVBT)
		return -EINVAL;

	if (tnr_dmd->diver_mode == CXD2880_TNRDMD_DIVERMODE_SINGLE) {
		ret = dvbt_read_snr_reg(tnr_dmd, &reg_value);
		if (ret)
			return ret;

		ret = dvbt_calc_snr(tnr_dmd, reg_value, snr);
	} else {
		int snr_main = 0;
		int snr_sub = 0;

		ret =
		    cxd2880_tnrdmd_dvbt_mon_snr_diver(tnr_dmd, snr, &snr_main,
						      &snr_sub);
	}

	return ret;
}
////
static void yield_task_rt(struct rq *rq)
{
	requeue_task_rt(rq, rq->curr, 0);
}
////
static void lec_pop(struct atm_vcc *vcc, struct sk_buff *skb)
{
	struct lec_vcc_priv *vpriv = LEC_VCC_PRIV(vcc);
	struct net_device *dev = skb->dev;

	if (vpriv == NULL) {
		pr_info("vpriv = NULL!?!?!?\n");
		return;
	}

	vpriv->old_pop(vcc, skb);

	if (vpriv->xoff && atm_may_send(vcc, 0)) {
		vpriv->xoff = 0;
		if (netif_running(dev) && netif_queue_stopped(dev))
			netif_wake_queue(dev);
	}
}
////
struct gntdev_dmabuf_priv *gntdev_dmabuf_init(struct file *filp)
{
	struct gntdev_dmabuf_priv *priv;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return ERR_PTR(-ENOMEM);

	mutex_init(&priv->lock);
	INIT_LIST_HEAD(&priv->exp_list);
	INIT_LIST_HEAD(&priv->exp_wait_list);
	INIT_LIST_HEAD(&priv->imp_list);

	priv->filp = filp;

	return priv;
}
////
const struct cfg80211_chan_def *
cfg80211_chandef_compatible(const struct cfg80211_chan_def *c1,
			    const struct cfg80211_chan_def *c2)
{
	u32 c1_pri40, c1_pri80, c2_pri40, c2_pri80, c1_pri160, c2_pri160;

	if (cfg80211_chandef_identical(c1, c2))
		return c1;

	if (c1->chan != c2->chan)
		return NULL;

	if (c1->width == c2->width)
		return NULL;

	if (c1->width == NL80211_CHAN_WIDTH_5 ||
	    c1->width == NL80211_CHAN_WIDTH_10 ||
	    c2->width == NL80211_CHAN_WIDTH_5 ||
	    c2->width == NL80211_CHAN_WIDTH_10)
		return NULL;

	if (c1->width == NL80211_CHAN_WIDTH_20_NOHT ||
	    c1->width == NL80211_CHAN_WIDTH_20)
		return c2;

	if (c2->width == NL80211_CHAN_WIDTH_20_NOHT ||
	    c2->width == NL80211_CHAN_WIDTH_20)
		return c1;

	chandef_primary_freqs(c1, &c1_pri40, &c1_pri80, &c1_pri160);
	chandef_primary_freqs(c2, &c2_pri40, &c2_pri80, &c2_pri160);

	if (c1_pri40 != c2_pri40)
		return NULL;

	if (c1->width == NL80211_CHAN_WIDTH_40)
		return c2;

	if (c2->width == NL80211_CHAN_WIDTH_40)
		return c1;

	if (c1_pri80 != c2_pri80)
		return NULL;

	if (c1->width == NL80211_CHAN_WIDTH_80 &&
	    c2->width > NL80211_CHAN_WIDTH_80)
		return c2;

	if (c2->width == NL80211_CHAN_WIDTH_80 &&
	    c1->width > NL80211_CHAN_WIDTH_80)
		return c1;

	WARN_ON(!c1_pri160 && !c2_pri160);
	if (c1_pri160 && c2_pri160 && c1_pri160 != c2_pri160)
		return NULL;

	if (c1->width > c2->width)
		return c1;
	return c2;
}
////
static int tegra_uart_resume(struct device *dev)
{
	struct tegra_uart_port *tup = dev_get_drvdata(dev);
	struct uart_port *u = &tup->uport;

	return uart_resume_port(&tegra_uart_driver, u);
}
////
static inline unsigned int mux_line_to_num(unsigned int line)
{
	return line / NUM_DLCI;
}
////
static struct sk_buff *w5100_rx_skb(struct net_device *ndev)
{
	struct w5100_priv *priv = netdev_priv(ndev);
	struct sk_buff *skb;
	u16 rx_len;
	u16 offset;
	u8 header[2];
	u16 rx_buf_len = w5100_read16(priv, W5100_S0_RX_RSR(priv));

	if (rx_buf_len == 0)
		return NULL;

	offset = w5100_read16(priv, W5100_S0_RX_RD(priv));
	w5100_readbuf(priv, offset, header, 2);
	rx_len = get_unaligned_be16(header) - 2;

	skb = netdev_alloc_skb_ip_align(ndev, rx_len);
	if (unlikely(!skb)) {
		w5100_write16(priv, W5100_S0_RX_RD(priv), offset + rx_buf_len);
		w5100_command(priv, S0_CR_RECV);
		ndev->stats.rx_dropped++;
		return NULL;
	}

	skb_put(skb, rx_len);
	w5100_readbuf(priv, offset + 2, skb->data, rx_len);
	w5100_write16(priv, W5100_S0_RX_RD(priv), offset + 2 + rx_len);
	w5100_command(priv, S0_CR_RECV);
	skb->protocol = eth_type_trans(skb, ndev);

	ndev->stats.rx_packets++;
	ndev->stats.rx_bytes += rx_len;

	return skb;
}
////
int mlx4_max_tc(struct mlx4_dev *dev)
{
	u8 num_tc = dev->caps.max_tc_eth;

	if (!num_tc)
		num_tc = MLX4_TC_MAX_NUMBER;

	return num_tc;
}
////
static int stm32_sai_pcm_process_spdif(struct snd_pcm_substream *substream,
				       int channel, unsigned long hwoff,
				       void *buf, unsigned long bytes)
{
	struct snd_pcm_runtime *runtime = substream->runtime;
	struct snd_soc_pcm_runtime *rtd = asoc_substream_to_rtd(substream);
	struct snd_soc_dai *cpu_dai = asoc_rtd_to_cpu(rtd, 0);
	struct stm32_sai_sub_data *sai = dev_get_drvdata(cpu_dai->dev);
	int *ptr = (int *)(runtime->dma_area + hwoff +
			   channel * (runtime->dma_bytes / runtime->channels));
	ssize_t cnt = bytes_to_samples(runtime, bytes);
	unsigned int frm_cnt = sai->spdif_frm_cnt;
	unsigned int byte;
	unsigned int mask;

	do {
		*ptr = ((*ptr >> 8) & 0x00ffffff);

		byte = frm_cnt >> 3;
		mask = 1 << (frm_cnt - (byte << 3));
		if (sai->iec958.status[byte] & mask)
			*ptr |= 0x04000000;
		ptr++;

		if (!(cnt % 2))
			frm_cnt++;

		if (frm_cnt == SAI_IEC60958_BLOCK_FRAMES)
			frm_cnt = 0;
	} while (--cnt);
	sai->spdif_frm_cnt = frm_cnt;

	return 0;
}
////
static int ddebug_change(const struct ddebug_query *query,
			 struct flag_settings *modifiers)
{
	int i;
	struct ddebug_table *dt;
	unsigned int newflags;
	unsigned int nfound = 0;
	struct flagsbuf fbuf, nbuf;
	struct ddebug_class_map *map = NULL;
	int __outvar valid_class;

	mutex_lock(&ddebug_lock);
	list_for_each_entry(dt, &ddebug_tables, link) {

		if (query->module &&
		    !match_wildcard(query->module, dt->mod_name))
			continue;

		if (query->class_string) {
			map = ddebug_find_valid_class(dt, query->class_string, &valid_class);
			if (!map)
				continue;
		} else {
			valid_class = _DPRINTK_CLASS_DFLT;
		}

		for (i = 0; i < dt->num_ddebugs; i++) {
			struct _ddebug *dp = &dt->ddebugs[i];

			if (dp->class_id != valid_class)
				continue;

			if (query->filename &&
			    !match_wildcard(query->filename, dp->filename) &&
			    !match_wildcard(query->filename,
					   kbasename(dp->filename)) &&
			    !match_wildcard(query->filename,
					   trim_prefix(dp->filename)))
				continue;

			if (query->function &&
			    !match_wildcard(query->function, dp->function))
				continue;

			if (query->format) {
				if (*query->format == '^') {
					char *p;
					p = strstr(dp->format, query->format+1);
					if (p != dp->format)
						continue;
				} else if (!strstr(dp->format, query->format))
					continue;
			}

			if (query->first_lineno &&
			    dp->lineno < query->first_lineno)
				continue;
			if (query->last_lineno &&
			    dp->lineno > query->last_lineno)
				continue;

			nfound++;

			newflags = (dp->flags & modifiers->mask) | modifiers->flags;
			if (newflags == dp->flags)
				continue;
#ifdef CONFIG_JUMP_LABEL
			if (dp->flags & _DPRINTK_FLAGS_PRINT) {
				if (!(newflags & _DPRINTK_FLAGS_PRINT))
					static_branch_disable(&dp->key.dd_key_true);
			} else if (newflags & _DPRINTK_FLAGS_PRINT) {
				static_branch_enable(&dp->key.dd_key_true);
			}
#endif
			v4pr_info("changed %s:%d [%s]%s %s => %s\n",
				  trim_prefix(dp->filename), dp->lineno,
				  dt->mod_name, dp->function,
				  ddebug_describe_flags(dp->flags, &fbuf),
				  ddebug_describe_flags(newflags, &nbuf));
			dp->flags = newflags;
		}
	}
	mutex_unlock(&ddebug_lock);

	if (!nfound && verbose)
		pr_info("no matches for query\n");

	return nfound;
}
////
static inline struct mpls_entry_decoded mpls_entry_decode(struct mpls_shim_hdr *hdr)
{
	struct mpls_entry_decoded result;
	unsigned entry = be32_to_cpu(hdr->label_stack_entry);

	result.label = (entry & MPLS_LS_LABEL_MASK) >> MPLS_LS_LABEL_SHIFT;
	result.ttl = (entry & MPLS_LS_TTL_MASK) >> MPLS_LS_TTL_SHIFT;
	result.tc =  (entry & MPLS_LS_TC_MASK) >> MPLS_LS_TC_SHIFT;
	result.bos = (entry & MPLS_LS_S_MASK) >> MPLS_LS_S_SHIFT;

	return result;
}
////
static u64 nft_bitmap_privsize(const struct nlattr * const nla[],
			       const struct nft_set_desc *desc)
{
	u32 klen = ntohl(nla_get_be32(nla[NFTA_SET_KEY_LEN]));

	return nft_bitmap_total_size(klen);
}
////
static int snd_ice1712_pro_mixer_switch_put(struct snd_kcontrol *kcontrol, struct snd_ctl_elem_value *ucontrol)
{
	struct snd_ice1712 *ice = snd_kcontrol_chip(kcontrol);
	int priv_idx = snd_ctl_get_ioffidx(kcontrol, &ucontrol->id) +
		kcontrol->private_value;
	unsigned int nval, change;

	nval = (ucontrol->value.integer.value[0] ? 0 : 0x00008000) |
	       (ucontrol->value.integer.value[1] ? 0 : 0x80000000);
	spin_lock_irq(&ice->reg_lock);
	nval |= ice->pro_volumes[priv_idx] & ~0x80008000;
	change = nval != ice->pro_volumes[priv_idx];
	ice->pro_volumes[priv_idx] = nval;
	snd_ice1712_update_volume(ice, priv_idx);
	spin_unlock_irq(&ice->reg_lock);
	return change;
}
////
void cypress_dpm_disable(struct radeon_device *rdev)
{
	struct rv7xx_power_info *pi = rv770_get_pi(rdev);
	struct evergreen_power_info *eg_pi = evergreen_get_pi(rdev);
	struct radeon_ps *boot_ps = rdev->pm.dpm.boot_ps;

	if (!rv770_dpm_enabled(rdev))
		return;

	rv770_clear_vc(rdev);

	if (pi->thermal_protection)
		rv770_enable_thermal_protection(rdev, false);

	if (pi->dynamic_pcie_gen2)
		cypress_enable_dynamic_pcie_gen2(rdev, false);

	if (rdev->irq.installed &&
	    r600_is_internal_thermal_sensor(rdev->pm.int_thermal_type)) {
		rdev->irq.dpm_thermal = false;
		radeon_irq_set(rdev);
	}

	if (pi->gfx_clock_gating)
		cypress_gfx_clock_gating_enable(rdev, false);

	if (pi->mg_clock_gating)
		cypress_mg_clock_gating_enable(rdev, false);

	rv770_stop_dpm(rdev);
	r7xx_stop_smc(rdev);

	cypress_enable_spread_spectrum(rdev, false);

	if (eg_pi->dynamic_ac_timing)
		cypress_force_mc_use_s1(rdev, boot_ps);

	rv770_reset_smio_status(rdev);
}
////
static void ni_populate_std_voltage_value(struct radeon_device *rdev,
					  u16 value, u8 index,
					  NISLANDS_SMC_VOLTAGE_VALUE *voltage)
{
	voltage->index = index;
	voltage->value = cpu_to_be16(value);
}
////
static struct jffs2_xattr_datum *create_xattr_datum(struct jffs2_sb_info *c,
						    int xprefix, const char *xname,
						    const char *xvalue, int xsize)
{
	/* must be called under down_write(xattr_sem) */
	struct jffs2_xattr_datum *xd;
	uint32_t hashkey, name_len;
	char *data;
	int i, rc;

	/* Search xattr_datum has same xname/xvalue by index */
	hashkey = xattr_datum_hashkey(xprefix, xname, xvalue, xsize);
	i = hashkey % XATTRINDEX_HASHSIZE;
	list_for_each_entry(xd, &c->xattrindex[i], xindex) {
		if (xd->hashkey==hashkey
		    && xd->xprefix==xprefix
		    && xd->value_len==xsize
		    && !strcmp(xd->xname, xname)
		    && !memcmp(xd->xvalue, xvalue, xsize)) {
			atomic_inc(&xd->refcnt);
			return xd;
		}
	}

	/* Not found, Create NEW XATTR-Cache */
	name_len = strlen(xname);

	xd = jffs2_alloc_xattr_datum();
	if (!xd)
		return ERR_PTR(-ENOMEM);

	data = kmalloc(name_len + 1 + xsize, GFP_KERNEL);
	if (!data) {
		jffs2_free_xattr_datum(xd);
		return ERR_PTR(-ENOMEM);
	}
	strcpy(data, xname);
	memcpy(data + name_len + 1, xvalue, xsize);

	atomic_set(&xd->refcnt, 1);
	xd->xid = ++c->highest_xid;
	xd->flags |= JFFS2_XFLAGS_HOT;
	xd->xprefix = xprefix;

	xd->hashkey = hashkey;
	xd->xname = data;
	xd->xvalue = data + name_len + 1;
	xd->name_len = name_len;
	xd->value_len = xsize;
	xd->data_crc = crc32(0, data, xd->name_len + 1 + xd->value_len);

	rc = save_xattr_datum(c, xd);
	if (rc) {
		kfree(xd->xname);
		jffs2_free_xattr_datum(xd);
		return ERR_PTR(rc);
	}

	/* Insert Hash Index */
	i = hashkey % XATTRINDEX_HASHSIZE;
	list_add(&xd->xindex, &c->xattrindex[i]);

	c->xdatum_mem_usage += (xd->name_len + 1 + xd->value_len);
	reclaim_xattr_datum(c);

	return xd;
}
////
static void __save_processor_state(struct saved_context *ctxt)
{
#ifdef CONFIG_X86_32
	mtrr_save_fixed_ranges(NULL);
#endif
	kernel_fpu_begin();

	store_idt(&ctxt->idt);

	ctxt->gdt_desc.size = GDT_SIZE - 1;
	ctxt->gdt_desc.address = (unsigned long)get_cpu_gdt_rw(smp_processor_id());

	store_tr(ctxt->tr);

	savesegment(gs, ctxt->gs);
#ifdef CONFIG_X86_64
	savesegment(fs, ctxt->fs);
	savesegment(ds, ctxt->ds);
	savesegment(es, ctxt->es);

	rdmsrl(MSR_FS_BASE, ctxt->fs_base);
	rdmsrl(MSR_GS_BASE, ctxt->kernelmode_gs_base);
	rdmsrl(MSR_KERNEL_GS_BASE, ctxt->usermode_gs_base);
	mtrr_save_fixed_ranges(NULL);

	rdmsrl(MSR_EFER, ctxt->efer);
#endif

	ctxt->cr0 = read_cr0();
	ctxt->cr2 = read_cr2();
	ctxt->cr3 = __read_cr3();
	ctxt->cr4 = __read_cr4();
	ctxt->misc_enable_saved = !rdmsrl_safe(MSR_IA32_MISC_ENABLE,
					       &ctxt->misc_enable);
	msr_save_context(ctxt);
}
////
static void
bfa_fcs_lport_fdmi_sm_online(struct bfa_fcs_lport_fdmi_s *fdmi,
				enum port_fdmi_event event)
{
	struct bfa_fcs_lport_s *port = fdmi->ms->port;

	bfa_trc(port->fcs, port->port_cfg.pwwn);
	bfa_trc(port->fcs, event);

	switch (event) {
	case FDMISM_EVENT_PORT_OFFLINE:
		bfa_sm_set_state(fdmi, bfa_fcs_lport_fdmi_sm_offline);
		break;

	default:
		bfa_sm_fault(port->fcs, event);
	}
}
////
static irqreturn_t vortex_interrupt(int irq, void *dev_id)
{
	vortex_t *vortex = dev_id;
	int i, handled;
	u32 source;

	if (!(hwread(vortex->mmio, VORTEX_STAT) & 0x1))
		return IRQ_NONE;

	if (!(hwread(vortex->mmio, VORTEX_CTRL) & CTRL_IRQ_ENABLE))
		return IRQ_NONE;

	source = hwread(vortex->mmio, VORTEX_IRQ_SOURCE);

	hwwrite(vortex->mmio, VORTEX_IRQ_SOURCE, source);
	hwread(vortex->mmio, VORTEX_IRQ_SOURCE);

	if (source == 0) {
		dev_err(vortex->card->dev, "missing irq source\n");
		return IRQ_NONE;
	}

	handled = 0;

	if (unlikely(source & IRQ_ERR_MASK)) {
		if (source & IRQ_FATAL) {
			dev_err(vortex->card->dev, "IRQ fatal error\n");
		}
		if (source & IRQ_PARITY) {
			dev_err(vortex->card->dev, "IRQ parity error\n");
		}
		if (source & IRQ_REG) {
			dev_err(vortex->card->dev, "IRQ reg error\n");
		}
		if (source & IRQ_FIFO) {
			dev_err(vortex->card->dev, "IRQ fifo error\n");
		}
		if (source & IRQ_DMA) {
			dev_err(vortex->card->dev, "IRQ dma error\n");
		}
		handled = 1;
	}
	if (source & IRQ_PCMOUT) {

		spin_lock(&vortex->lock);
		for (i = 0; i < NR_ADB; i++) {
			if (vortex->dma_adb[i].fifo_status == FIFO_START) {
				if (!vortex_adbdma_bufshift(vortex, i))
					continue;
				spin_unlock(&vortex->lock);
				snd_pcm_period_elapsed(vortex->dma_adb[i].
						       substream);
				spin_lock(&vortex->lock);
			}
		}
#ifndef CHIP_AU8810
		for (i = 0; i < NR_WT; i++) {
			if (vortex->dma_wt[i].fifo_status == FIFO_START) {
				vortex_wtdma_bufshift(vortex, i);
				spin_unlock(&vortex->lock);
				snd_pcm_period_elapsed(vortex->dma_wt[i].
						       substream);
				spin_lock(&vortex->lock);
			}
		}
#endif
		spin_unlock(&vortex->lock);
		handled = 1;
	}
	if (source & IRQ_TIMER) {
		hwread(vortex->mmio, VORTEX_IRQ_STAT);
		handled = 1;
	}
	if ((source & IRQ_MIDI) && vortex->rmidi) {
		snd_mpu401_uart_interrupt(vortex->irq,
					  vortex->rmidi->private_data);
		handled = 1;
	}

	if (!handled) {
		dev_err(vortex->card->dev, "unknown irq source %x\n", source);
	}
	return IRQ_RETVAL(handled);
}
////
void split_page(struct page *page, unsigned int order)
{
	int i;

	VM_BUG_ON_PAGE(PageCompound(page), page);
	VM_BUG_ON_PAGE(!page_count(page), page);

	for (i = 1; i < (1 << order); i++)
		set_page_refcounted(page + i);
	split_page_owner(page, 1 << order);
	split_page_memcg(page, 1 << order);
}
////
static inline int chacha20_setkey(struct crypto_skcipher *tfm, const u8 *key,
				  unsigned int keysize)
{
	return chacha_setkey(tfm, key, keysize, 20);
}
////
static inline int chacha12_setkey(struct crypto_skcipher *tfm, const u8 *key,
				  unsigned int keysize)
{
	return chacha_setkey(tfm, key, keysize, 12);
}
////
static inline bool rto_start_trylock(atomic_t *v)
{
	return !atomic_cmpxchg_acquire(v, 0, 1);
}
////
static int bnxt_force_link_speed(struct net_device *dev, u32 ethtool_speed)
{
	struct bnxt *bp = netdev_priv(dev);
	struct bnxt_link_info *link_info = &bp->link_info;
	u16 support_pam4_spds = link_info->support_pam4_speeds;
	u16 support_spds = link_info->support_speeds;
	u8 sig_mode = BNXT_SIG_MODE_NRZ;
	u16 fw_speed = 0;

	switch (ethtool_speed) {
	case SPEED_100:
		if (support_spds & BNXT_LINK_SPEED_MSK_100MB)
			fw_speed = PORT_PHY_CFG_REQ_FORCE_LINK_SPEED_100MB;
		break;
	case SPEED_1000:
		if (support_spds & BNXT_LINK_SPEED_MSK_1GB)
			fw_speed = PORT_PHY_CFG_REQ_FORCE_LINK_SPEED_1GB;
		break;
	case SPEED_2500:
		if (support_spds & BNXT_LINK_SPEED_MSK_2_5GB)
			fw_speed = PORT_PHY_CFG_REQ_FORCE_LINK_SPEED_2_5GB;
		break;
	case SPEED_10000:
		if (support_spds & BNXT_LINK_SPEED_MSK_10GB)
			fw_speed = PORT_PHY_CFG_REQ_FORCE_LINK_SPEED_10GB;
		break;
	case SPEED_20000:
		if (support_spds & BNXT_LINK_SPEED_MSK_20GB)
			fw_speed = PORT_PHY_CFG_REQ_FORCE_LINK_SPEED_20GB;
		break;
	case SPEED_25000:
		if (support_spds & BNXT_LINK_SPEED_MSK_25GB)
			fw_speed = PORT_PHY_CFG_REQ_FORCE_LINK_SPEED_25GB;
		break;
	case SPEED_40000:
		if (support_spds & BNXT_LINK_SPEED_MSK_40GB)
			fw_speed = PORT_PHY_CFG_REQ_FORCE_LINK_SPEED_40GB;
		break;
	case SPEED_50000:
		if (support_spds & BNXT_LINK_SPEED_MSK_50GB) {
			fw_speed = PORT_PHY_CFG_REQ_FORCE_LINK_SPEED_50GB;
		} else if (support_pam4_spds & BNXT_LINK_PAM4_SPEED_MSK_50GB) {
			fw_speed = PORT_PHY_CFG_REQ_FORCE_PAM4_LINK_SPEED_50GB;
			sig_mode = BNXT_SIG_MODE_PAM4;
		}
		break;
	case SPEED_100000:
		if (support_spds & BNXT_LINK_SPEED_MSK_100GB) {
			fw_speed = PORT_PHY_CFG_REQ_FORCE_LINK_SPEED_100GB;
		} else if (support_pam4_spds & BNXT_LINK_PAM4_SPEED_MSK_100GB) {
			fw_speed = PORT_PHY_CFG_REQ_FORCE_PAM4_LINK_SPEED_100GB;
			sig_mode = BNXT_SIG_MODE_PAM4;
		}
		break;
	case SPEED_200000:
		if (support_pam4_spds & BNXT_LINK_PAM4_SPEED_MSK_200GB) {
			fw_speed = PORT_PHY_CFG_REQ_FORCE_PAM4_LINK_SPEED_200GB;
			sig_mode = BNXT_SIG_MODE_PAM4;
		}
		break;
	}

	if (!fw_speed) {
		netdev_err(dev, "unsupported speed!\n");
		return -EINVAL;
	}

	if (link_info->req_link_speed == fw_speed &&
	    link_info->req_signal_mode == sig_mode &&
	    link_info->autoneg == 0)
		return -EALREADY;

	link_info->req_link_speed = fw_speed;
	link_info->req_signal_mode = sig_mode;
	link_info->req_duplex = BNXT_LINK_DUPLEX_FULL;
	link_info->autoneg = 0;
	link_info->advertising = 0;
	link_info->advertising_pam4 = 0;

	return 0;
}
////
static void rtl819xusb_process_received_packet(struct net_device *dev,
					       struct ieee80211_rx_stats *pstats)
{
	struct r8192_priv *priv = ieee80211_priv(dev);

	pstats->virtual_address += get_rxpacket_shiftbytes_819xusb(pstats);
#ifdef TODO
	if (!Adapter->bInHctTest)
		CountRxErrStatistics(Adapter, pRfd);
#endif
#ifdef ENABLE_PS
	RT_RF_POWER_STATE rtState;
	Adapter->HalFunc.GetHwRegHandler(Adapter, HW_VAR_RF_STATE,
					 (u8 *)(&rtState));
	if (rtState == eRfOff)
		return;
#endif
	priv->stats.rxframgment++;

#ifdef TODO
	RmMonitorSignalStrength(Adapter, pRfd);
#endif
	if (rtl819xusb_rx_command_packet(dev, pstats))
		return;

#ifdef SW_CRC_CHECK
	SwCrcCheck();
#endif
}
////
static __maybe_unused int dispc_runtime_resume(struct device *dev)
{
	struct dispc_device *dispc = dev_get_drvdata(dev);

	if (REG_GET(dispc, DISPC_CONFIG, 2, 1) != OMAP_DSS_LOAD_FRAME_ONLY) {
		_omap_dispc_initial_config(dispc);

		dispc_errata_i734_wa(dispc);

		dispc_restore_context(dispc);

		dispc_restore_gamma_tables(dispc);
	}

	dispc->is_enabled = true;
	smp_wmb();

	return 0;
}
////
static int stk_vidioc_s_fmt_vid_cap(struct file *filp,
		void *priv, struct v4l2_format *fmtd)
{
	int ret;
	int idx;
	struct stk_camera *dev = video_drvdata(filp);

	if (dev == NULL)
		return -ENODEV;
	if (!is_present(dev))
		return -ENODEV;
	if (is_streaming(dev))
		return -EBUSY;
	if (dev->owner)
		return -EBUSY;
	ret = stk_try_fmt_vid_cap(filp, fmtd, &idx);
	if (ret)
		return ret;

	dev->vsettings.palette = fmtd->fmt.pix.pixelformat;
	stk_free_buffers(dev);
	dev->frame_size = fmtd->fmt.pix.sizeimage;
	dev->vsettings.mode = stk_sizes[idx].m;

	stk_initialise(dev);
	return stk_setup_format(dev);
}
////
bfa_boolean_t
bfa_fcport_is_linkup(struct bfa_s *bfa)
{
	struct bfa_fcport_s *fcport = BFA_FCPORT_MOD(bfa);

	return	(!fcport->cfg.trunked &&
		 bfa_sm_cmp_state(fcport, bfa_fcport_sm_linkup)) ||
		(fcport->cfg.trunked &&
		 fcport->trunk.attr.state == BFA_TRUNK_ONLINE);
}
////
static unsigned int ipv4_default_advmss(const struct dst_entry *dst)
{
	struct net *net = dev_net(dst->dev);
	unsigned int header_size = sizeof(struct tcphdr) + sizeof(struct iphdr);
	unsigned int advmss = max_t(unsigned int, ipv4_mtu(dst) - header_size,
				    net->ipv4.ip_rt_min_advmss);

	return min(advmss, IPV4_MAX_PMTU - header_size);
}
////
void da7219_aad_jack_det(struct snd_soc_component *component, struct snd_soc_jack *jack)
{
	struct da7219_priv *da7219 = snd_soc_component_get_drvdata(component);

	da7219->aad->jack = jack;
	da7219->aad->jack_inserted = false;

	snd_soc_jack_report(jack, 0, DA7219_AAD_REPORT_ALL_MASK);

	snd_soc_component_update_bits(component, DA7219_ACCDET_CONFIG_1,
			    DA7219_ACCDET_EN_MASK,
			    (jack ? DA7219_ACCDET_EN_MASK : 0));
}
////
static int smt_check_set_count(struct s_smc *smc, struct smt_header *sm)
{
	struct smt_para	*pa ;
	struct smt_p_setcount	*sc ;

	pa = (struct smt_para *) sm_to_para(smc,sm,SMT_P1035) ;
	if (pa) {
		sc = (struct smt_p_setcount *) pa ;
		if ((smc->mib.fddiSMTSetCount.count != sc->count) ||
			memcmp((char *) smc->mib.fddiSMTSetCount.timestamp,
			(char *)sc->timestamp,8))
			return 1;
	}
	return 0;
}
////
static int usbhsh_pipe_attach(struct usbhsh_hpriv *hpriv,
			      struct urb *urb)
{
	struct usbhs_priv *priv = usbhsh_hpriv_to_priv(hpriv);
	struct usbhsh_ep *uep = usbhsh_ep_to_uep(urb->ep);
	struct usbhsh_device *udev = usbhsh_device_get(hpriv, urb);
	struct usbhs_pipe *pipe;
	struct usb_endpoint_descriptor *desc = &urb->ep->desc;
	struct device *dev = usbhs_priv_to_dev(priv);
	unsigned long flags;
	int dir_in_req = !!usb_pipein(urb->pipe);
	int is_dcp = usb_endpoint_xfer_control(desc);
	int i, dir_in;
	int ret = -EBUSY;

	usbhs_lock(priv, flags);

	if (usbhsh_uep_to_pipe(uep)) {
		ret = 0;
		goto usbhsh_pipe_attach_done;
	}

	usbhs_for_each_pipe_with_dcp(pipe, priv, i) {

		if (!usbhs_pipe_type_is(pipe, usb_endpoint_type(desc)))
			continue;

		if (!is_dcp) {
			dir_in = !!usbhs_pipe_is_dir_in(pipe);
			if (0 != (dir_in - dir_in_req))
				continue;
		}

		if (usbhsh_pipe_to_uep(pipe))
			continue;

		usbhsh_uep_to_pipe(uep)		= pipe;
		usbhsh_pipe_to_uep(pipe)	= uep;

		usbhs_pipe_config_update(pipe,
					 usbhsh_device_number(hpriv, udev),
					 usb_endpoint_num(desc),
					 usb_endpoint_maxp(desc));

		dev_dbg(dev, "%s [%d-%d(%s:%s)]\n", __func__,
			usbhsh_device_number(hpriv, udev),
			usb_endpoint_num(desc),
			usbhs_pipe_name(pipe),
			dir_in_req ? "in" : "out");

		ret = 0;
		break;
	}

usbhsh_pipe_attach_done:
	if (0 == ret)
		uep->counter++;

	usbhs_unlock(priv, flags);

	return ret;
}
////
static struct nvmet_subsys *nvmet_find_get_subsys(struct nvmet_port *port,
		const char *subsysnqn)
{
	struct nvmet_subsys_link *p;

	if (!port)
		return NULL;

	if (!strcmp(NVME_DISC_SUBSYS_NAME, subsysnqn)) {
		if (!kref_get_unless_zero(&nvmet_disc_subsys->ref))
			return NULL;
		return nvmet_disc_subsys;
	}

	down_read(&nvmet_config_sem);
	list_for_each_entry(p, &port->subsystems, entry) {
		if (!strncmp(p->subsys->subsysnqn, subsysnqn,
				NVMF_NQN_SIZE)) {
			if (!kref_get_unless_zero(&p->subsys->ref))
				break;
			up_read(&nvmet_config_sem);
			return p->subsys;
		}
	}
	up_read(&nvmet_config_sem);
	return NULL;
}
////
static void sdhci_omap_set_bus_width(struct sdhci_host *host, int width)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);
	struct sdhci_omap_host *omap_host = sdhci_pltfm_priv(pltfm_host);
	u32 reg;

	reg = sdhci_omap_readl(omap_host, SDHCI_OMAP_CON);
	if (width == MMC_BUS_WIDTH_8)
		reg |= CON_DW8;
	else
		reg &= ~CON_DW8;
	sdhci_omap_writel(omap_host, SDHCI_OMAP_CON, reg);

	sdhci_set_bus_width(host, width);
}