/*
    This is the public interface for verifying model proofs. This function abstracts 
    away the underlying proving system so the verifier doesn't need to know which
    proving system is used.
 */
pub fn verify(vk: String, proof: String, public_vals: &[String], config: String) {
    let config_buf = hex::decode(config).unwrap();
    let config = rmp_serde::from_slice(&config_buf).unwrap();
    ModelCircuit::<Fr>::generate_from_msgpack(config, false);

    let vk = VerifyingKey::read::<BufReader<_>, ModelCircuit<Fr>>(
        &mut BufReader::new(hex::decode(&vk).unwrap().as_slice()),
        SerdeFormat::RawBytes,
        (),
    )
    .unwrap();
    println!("Loaded vkey");

    let proof = hex::decode(proof).unwrap();

    let public_vals: Vec<Fr> = public_vals
        .iter()
        .map(|x| Fr::from_str_vartime(x).unwrap())
        .collect();

    let params = ParamsKZG::<Bn256> {
        k: 24,
        n: 1 << 24,
        g: vec![G1Affine::generator()],
        g_lagrange: vec![],
        s_g2: G2Affine {
        x: Fq2::new(
            Fq::from_str_vartime(
            "17109015867118572030745779324212191698736396241608212876854183006212164292849",
            )
            .unwrap(),
            Fq::from_str_vartime(
            "10938796003451079337728171122795908661206257899267762973177153171611833735690",
            )
            .unwrap(),
        ),
        y: Fq2::new(
            Fq::from_str_vartime(
            "5207198165565673371403386229903402585220628358261245511764422372679613157540",
            )
            .unwrap(),
            Fq::from_str_vartime(
            "14794195211544794432532285509939829643330163063517964588789563791156406265496",
            )
            .unwrap(),
        ),
        },
        g2: G2Affine {
        x: Fq2::new(
            Fq::from_str_vartime(
            "10857046999023057135944570762232829481370756359578518086990519993285655852781",
            )
            .unwrap(),
            Fq::from_str_vartime(
            "11559732032986387107991004021392285783925812861821192530917403151452391805634",
            )
            .unwrap(),
        ),
        y: Fq2::new(
            Fq::from_str_vartime(
            "8495653923123431417604973247489272438418190587263600148770280649306958101930",
            )
            .unwrap(),
            Fq::from_str_vartime(
            "4082367875863433681332203403145435568316851327593401208105741076214120093531",
            )
            .unwrap(),
        ),
        },
    };

    let strategy = SingleStrategy::new(&params);

    let transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    println!("Loaded configuration");
    println!("public_vals: {:?}", public_vals);
    verify_kzg(&params, &vk, strategy, &public_vals, transcript);
}